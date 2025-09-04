import dns.resolver
import dns.zone
import dns.query
import socket
from typing import List, Dict, Optional, Any
from sqlalchemy.orm import Session
from app.db import models
import logging

logger = logging.getLogger(__name__)

class DNSService:
    def __init__(self, db: Session):
        self.db = db
        self.resolver = dns.resolver.Resolver()
        
    def lookup_hostname(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            
            # Store DNS record
            self._store_dns_record(hostname, 'PTR', ip_address)
            
            return hostname
        except (socket.herror, socket.gaierror) as e:
            logger.debug(f"Reverse DNS lookup failed for {ip_address}: {str(e)}")
            return None
    
    def resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses"""
        ip_addresses = []
        
        try:
            # A records (IPv4)
            try:
                answers = self.resolver.resolve(hostname, 'A')
                for answer in answers:
                    ip = str(answer)
                    ip_addresses.append(ip)
                    self._store_dns_record(hostname, 'A', ip, answer.ttl)
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            
            # AAAA records (IPv6)
            try:
                answers = self.resolver.resolve(hostname, 'AAAA')
                for answer in answers:
                    ip = str(answer)
                    ip_addresses.append(ip)
                    self._store_dns_record(hostname, 'AAAA', ip, answer.ttl)
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
                
        except Exception as e:
            logger.warning(f"DNS resolution failed for {hostname}: {str(e)}")
        
        return ip_addresses
    
    def get_dns_records(self, hostname: str, record_types: List[str] = None) -> Dict[str, List[str]]:
        """Get various DNS records for a hostname"""
        if record_types is None:
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
        
        records = {}
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(hostname, record_type)
                record_values = []
                
                for answer in answers:
                    value = str(answer)
                    record_values.append(value)
                    self._store_dns_record(hostname, record_type, value, answer.ttl)
                
                if record_values:
                    records[record_type] = record_values
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                logger.warning(f"Failed to get {record_type} records for {hostname}: {str(e)}")
        
        return records
    
    def attempt_zone_transfer(self, hostname: str, nameservers: List[str] = None) -> Dict[str, Any]:
        """Attempt DNS zone transfer for a domain"""
        zone_data = {
            'success': False,
            'records': [],
            'error': None,
            'nameserver_used': None
        }
        
        # Get nameservers if not provided
        if not nameservers:
            try:
                ns_records = self.resolver.resolve(hostname, 'NS')
                nameservers = [str(ns).rstrip('.') for ns in ns_records]
            except Exception as e:
                zone_data['error'] = f"Failed to get nameservers: {str(e)}"
                return zone_data
        
        # Try zone transfer with each nameserver
        for ns in nameservers:
            try:
                # Try to get the IP of the nameserver
                ns_ips = self.resolve_hostname(ns)
                if not ns_ips:
                    continue
                
                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ips[0], hostname))
                
                # Parse zone records
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            record = {
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'value': str(rdata),
                                'ttl': rdataset.ttl
                            }
                            records.append(record)
                            
                            # Store in database
                            full_name = f"{name}.{hostname}" if name != '@' else hostname
                            self._store_dns_record(
                                full_name, 
                                dns.rdatatype.to_text(rdataset.rdtype), 
                                str(rdata), 
                                rdataset.ttl
                            )
                
                zone_data.update({
                    'success': True,
                    'records': records,
                    'nameserver_used': ns
                })
                
                logger.info(f"Zone transfer successful for {hostname} using {ns}")
                break
                
            except Exception as e:
                logger.debug(f"Zone transfer failed for {hostname} using {ns}: {str(e)}")
                continue
        
        if not zone_data['success']:
            zone_data['error'] = "Zone transfer failed with all nameservers"
        
        return zone_data
    
    def enrich_host_data(self, host: models.Host) -> Dict[str, Any]:
        """Enrich host data with DNS information"""
        enrichment_data = {
            'reverse_dns': None,
            'dns_records': {},
            'zone_transfer': None
        }
        
        # Perform reverse DNS lookup
        if host.ip_address:
            hostname = self.lookup_hostname(host.ip_address)
            if hostname:
                host.hostname = hostname
                enrichment_data['reverse_dns'] = hostname
                
                # Get additional DNS records for the hostname
                dns_records = self.get_dns_records(hostname)
                enrichment_data['dns_records'] = dns_records
                
                # Extract domain for zone transfer attempt
                domain_parts = hostname.split('.')
                if len(domain_parts) >= 2:
                    domain = '.'.join(domain_parts[-2:])  # Get root domain
                    zone_transfer_result = self.attempt_zone_transfer(domain)
                    if zone_transfer_result['success']:
                        enrichment_data['zone_transfer'] = zone_transfer_result
        
        # If hostname was already known, get DNS records
        elif host.hostname:
            dns_records = self.get_dns_records(host.hostname)
            enrichment_data['dns_records'] = dns_records
            
            # Attempt zone transfer
            domain_parts = host.hostname.split('.')
            if len(domain_parts) >= 2:
                domain = '.'.join(domain_parts[-2:])
                zone_transfer_result = self.attempt_zone_transfer(domain)
                if zone_transfer_result['success']:
                    enrichment_data['zone_transfer'] = zone_transfer_result
        
        self.db.commit()
        return enrichment_data
    
    def _store_dns_record(self, domain: str, record_type: str, value: str, ttl: int = None):
        """Store DNS record in database"""
        try:
            # Check if record already exists
            existing = self.db.query(models.DNSRecord).filter(
                models.DNSRecord.domain == domain,
                models.DNSRecord.record_type == record_type,
                models.DNSRecord.value == value
            ).first()
            
            if existing:
                # Update TTL if provided
                if ttl is not None:
                    existing.ttl = ttl
            else:
                # Create new record
                dns_record = models.DNSRecord(
                    domain=domain,
                    record_type=record_type,
                    value=value,
                    ttl=ttl
                )
                self.db.add(dns_record)
                
        except Exception as e:
            logger.warning(f"Failed to store DNS record for {domain}: {str(e)}")
    
    def get_stored_dns_records(self, domain: str) -> List[models.DNSRecord]:
        """Get stored DNS records for a domain"""
        return self.db.query(models.DNSRecord).filter(
            models.DNSRecord.domain == domain
        ).all()