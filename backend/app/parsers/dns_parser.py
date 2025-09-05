import csv
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session
from app.db import models
from app.services.subnet_correlation import SubnetCorrelationService
import logging
import time

logger = logging.getLogger(__name__)

class DNSParser:
    def __init__(self, db: Session):
        self.db = db
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse DNS records CSV file and create/update host records with DNS names"""
        start_time = time.time()
        logger.info(f"Starting DNS parse of {filename}")
        
        try:
            result = self._parse_csv_file(file_path, filename)
            elapsed_time = time.time() - start_time
            logger.info(f"Successfully parsed DNS {filename} in {elapsed_time:.2f} seconds")
            return result
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Error parsing DNS file {filename} after {elapsed_time:.2f} seconds: {str(e)}")
            raise

    def _parse_csv_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse DNS CSV file with columns: record_type, name, address"""
        # Create scan record
        scan = models.Scan(
            filename=filename,
            scan_type='dns_records',
            tool_name='dns',
            created_at=datetime.utcnow()
        )
        
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        
        hosts_created = 0
        hosts_updated = 0
        dns_records_processed = 0
        out_of_scope_count = 0
        
        with open(file_path, 'r', encoding='utf-8') as csvfile:
            # Try to detect the CSV format
            sample = csvfile.read(1024)
            csvfile.seek(0)
            
            # Detect delimiter
            delimiter = ','
            if '\t' in sample:
                delimiter = '\t'
            elif ';' in sample:
                delimiter = ';'
            
            reader = csv.DictReader(csvfile, delimiter=delimiter)
            rows = list(reader)
            logger.info(f"Processing {len(rows)} DNS records from CSV")
            
            for i, row in enumerate(rows, 1):
                if i % 100 == 0 or i == 1:  # Log progress every 100 rows
                    logger.info(f"Processing DNS record {i}/{len(rows)} ({i/len(rows)*100:.1f}%)")
                
                try:
                    # Normalize column names (handle different possible formats)
                    normalized_row = self._normalize_row_keys(row)
                    
                    # Extract data from row
                    record_type = normalized_row.get('record_type', '').strip().upper()
                    dns_name = normalized_row.get('name', '').strip()
                    ip_address = normalized_row.get('address', '').strip()
                    
                    # Skip invalid rows
                    if not all([record_type, dns_name, ip_address]):
                        logger.warning(f"Skipping row {i}: missing required fields - record_type: {record_type}, name: {dns_name}, address: {ip_address}")
                        continue
                    
                    # Validate IP address format
                    if not self._is_valid_ip(ip_address):
                        logger.warning(f"Skipping row {i}: invalid IP address format: {ip_address}")
                        continue
                    
                    # Process PTR records (reverse DNS lookups)
                    if record_type == 'PTR':
                        # Create or update DNS record
                        dns_record = models.DNSRecord(
                            domain=dns_name,
                            record_type=record_type,
                            value=ip_address
                        )
                        self.db.add(dns_record)
                        dns_records_processed += 1
                        
                        # Check if IP is in scope
                        matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
                        
                        if matching_subnets:
                            # Look for existing host with this IP address
                            existing_host = self.db.query(models.Host).filter(
                                models.Host.ip_address == ip_address
                            ).first()
                            
                            if existing_host:
                                # Update existing host with DNS name if it doesn't have one
                                if not existing_host.hostname or existing_host.hostname != dns_name:
                                    logger.info(f"Updating host {ip_address} with DNS name: {dns_name}")
                                    existing_host.hostname = dns_name
                                    hosts_updated += 1
                                else:
                                    logger.debug(f"Host {ip_address} already has hostname: {existing_host.hostname}")
                            else:
                                # Create new host record
                                logger.info(f"Creating new host record for {ip_address} with DNS name: {dns_name}")
                                new_host = models.Host(
                                    scan_id=scan.id,
                                    ip_address=ip_address,
                                    hostname=dns_name,
                                    state='unknown'  # We don't know the state from DNS records
                                )
                                self.db.add(new_host)
                                hosts_created += 1
                        else:
                            # Handle out-of-scope host
                            logger.debug(f"IP {ip_address} is out of scope, creating out-of-scope record")
                            out_of_scope = models.OutOfScopeHost(
                                scan_id=scan.id,
                                ip_address=ip_address,
                                hostname=dns_name,
                                ports={'dns_info': {'record_type': record_type, 'dns_name': dns_name}},
                                tool_source='dns',
                                reason='IP address not found in any defined subnet scope'
                            )
                            self.db.add(out_of_scope)
                            out_of_scope_count += 1
                    else:
                        # For other record types (A, AAAA, CNAME, etc.), just store the DNS record
                        logger.debug(f"Processing non-PTR record: {record_type} {dns_name} -> {ip_address}")
                        dns_record = models.DNSRecord(
                            domain=dns_name,
                            record_type=record_type,
                            value=ip_address
                        )
                        self.db.add(dns_record)
                        dns_records_processed += 1
                        
                except Exception as e:
                    logger.warning(f"Error processing DNS record row {i}: {str(e)}")
                    continue
        
        # Correlate any new hosts to subnets
        if hosts_created > 0:
            logger.info(f"Starting subnet correlation for {hosts_created} new hosts")
            try:
                correlation_start = time.time()
                mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
                correlation_time = time.time() - correlation_start
                logger.info(f"Created {mappings_created} host-subnet mappings in {correlation_time:.2f} seconds")
            except Exception as e:
                logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
        
        # Commit all changes
        logger.info(f"Committing DNS parsing results to database")
        self.db.commit()
        
        logger.info(f"DNS parsing complete - Created: {hosts_created} hosts, Updated: {hosts_updated} hosts, "
                   f"Processed: {dns_records_processed} DNS records, Out of scope: {out_of_scope_count}")
        
        return scan

    def _normalize_row_keys(self, row: Dict[str, str]) -> Dict[str, str]:
        """Normalize CSV column names to handle different formats"""
        normalized = {}
        
        for key, value in row.items():
            key_lower = key.lower().strip()
            
            # Map various column name formats to standard names
            if key_lower in ['record_type', 'recordtype', 'type', 'record type']:
                normalized['record_type'] = value
            elif key_lower in ['name', 'domain', 'dns_name', 'hostname', 'host']:
                normalized['name'] = value
            elif key_lower in ['address', 'ip_address', 'ip', 'value', 'target']:
                normalized['address'] = value
            elif key_lower in ['ttl', 'time_to_live']:
                normalized['ttl'] = value
            else:
                # Keep original key if no mapping found
                normalized[key] = value
        
        return normalized

    def _is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format (supports both IPv4 and IPv6)"""
        # IPv4 pattern
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        
        return bool(re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address))