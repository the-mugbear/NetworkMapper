import xml.etree.ElementTree as ET
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session
from app.db import models
from app.services.subnet_correlation import SubnetCorrelationService
import logging

logger = logging.getLogger(__name__)

class MasscanParser:
    def __init__(self, db: Session):
        self.db = db
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan output files (XML, JSON, or list format)"""
        try:
            if filename.lower().endswith('.xml'):
                return self._parse_xml_file(file_path, filename)
            elif filename.lower().endswith('.json'):
                return self._parse_json_file(file_path, filename)
            else:
                # Assume list format (default masscan output)
                return self._parse_list_file(file_path, filename)
        except Exception as e:
            logger.error(f"Error parsing Masscan file {filename}: {str(e)}")
            raise

    def _parse_xml_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan XML output"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Create scan record
        scan = models.Scan(
            filename=filename,
            scan_type='port_scan',
            tool_name='masscan',
            version=root.get('version'),
            command_line=root.get('args'),
            start_time=self._parse_timestamp(root.get('start')),
            created_at=datetime.utcnow()
        )
        
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        
        # Parse hosts and ports
        hosts_data = {}
        out_of_scope_hosts = {}
        
        for host_elem in root.findall('host'):
            # Get IP address
            addr_elem = host_elem.find('address')
            if addr_elem is None:
                continue
                
            ip_address = addr_elem.get('addr')
            if not ip_address:
                continue
            
            # Check if IP is in scope
            matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
            
            # Get host state
            status_elem = host_elem.find('status')
            state = status_elem.get('state') if status_elem is not None else 'unknown'
            
            # Skip hosts that are down or filtered - they provide no useful information
            if state in ['down', 'filtered']:
                continue
            
            # Check if host has any meaningful data (open ports)
            has_meaningful_data = False
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    state_elem = port_elem.find('state')
                    port_state = state_elem.get('state') if state_elem is not None else 'unknown'
                    if port_state == 'open':
                        has_meaningful_data = True
                        break
            
            # Skip hosts with no meaningful data
            if not has_meaningful_data:
                continue
            
            if matching_subnets:
                # Create or get host record
                if ip_address not in hosts_data:
                    host = models.Host(
                        scan_id=scan.id,
                        ip_address=ip_address,
                        state=state
                    )
                    self.db.add(host)
                    self.db.flush()
                    hosts_data[ip_address] = host
                else:
                    host = hosts_data[ip_address]
                
                # Parse ports
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        port_number = int(port_elem.get('portid'))
                        protocol = port_elem.get('protocol')
                        
                        # Get port state
                        state_elem = port_elem.find('state')
                        port_state = state_elem.get('state') if state_elem is not None else 'unknown'
                        
                        port = models.Port(
                            host_id=host.id,
                            port_number=port_number,
                            protocol=protocol,
                            state=port_state
                        )
                        self.db.add(port)
            else:
                # Handle out-of-scope host
                ports = []
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        ports.append({
                            'port': int(port_elem.get('portid')),
                            'protocol': port_elem.get('protocol'),
                            'state': port_elem.find('state').get('state') if port_elem.find('state') is not None else 'unknown'
                        })
                
                out_of_scope = models.OutOfScopeHost(
                    scan_id=scan.id,
                    ip_address=ip_address,
                    ports={'masscan_ports': ports},
                    tool_source='masscan',
                    reason='IP address not found in any defined subnet scope'
                )
                self.db.add(out_of_scope)
                out_of_scope_hosts[ip_address] = out_of_scope
        
        # Correlate hosts to subnets
        try:
            mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
            logger.info(f"Created {mappings_created} host-subnet mappings for Masscan scan {scan.id}")
        except Exception as e:
            logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
        
        self.db.commit()
        
        logger.info(f"Processed {len(hosts_data)} in-scope hosts and {len(out_of_scope_hosts)} out-of-scope hosts from Masscan XML")
        return scan

    def _parse_json_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan JSON output"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Create scan record
        scan = models.Scan(
            filename=filename,
            scan_type='port_scan',
            tool_name='masscan',
            created_at=datetime.utcnow()
        )
        
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        
        hosts_data = {}
        out_of_scope_count = 0
        
        for entry in data:
            ip_address = entry.get('ip')
            if not ip_address:
                continue
            
            # Check if host has any meaningful data (open ports)
            has_meaningful_data = False
            for port_info in entry.get('ports', []):
                port_status = port_info.get('status', 'open')
                if port_status == 'open':
                    has_meaningful_data = True
                    break
            
            # Skip hosts with no meaningful data
            if not has_meaningful_data:
                continue
            
            # Check if IP is in scope
            matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
            
            if matching_subnets:
                # Create or get host record
                if ip_address not in hosts_data:
                    host = models.Host(
                        scan_id=scan.id,
                        ip_address=ip_address,
                        state='up'
                    )
                    self.db.add(host)
                    self.db.flush()
                    hosts_data[ip_address] = host
                else:
                    host = hosts_data[ip_address]
                
                # Add port information
                for port_info in entry.get('ports', []):
                    port = models.Port(
                        host_id=host.id,
                        port_number=port_info.get('port'),
                        protocol=port_info.get('proto'),
                        state=port_info.get('status', 'open')
                    )
                    self.db.add(port)
            else:
                # Handle out-of-scope host
                out_of_scope = models.OutOfScopeHost(
                    scan_id=scan.id,
                    ip_address=ip_address,
                    ports={'masscan_ports': entry.get('ports', [])},
                    tool_source='masscan',
                    reason='IP address not found in any defined subnet scope'
                )
                self.db.add(out_of_scope)
                out_of_scope_count += 1
        
        # Correlate hosts to subnets
        try:
            mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
            logger.info(f"Created {mappings_created} host-subnet mappings for Masscan scan {scan.id}")
        except Exception as e:
            logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
        
        self.db.commit()
        
        logger.info(f"Processed {len(hosts_data)} in-scope hosts and {out_of_scope_count} out-of-scope hosts from Masscan JSON")
        return scan

    def _parse_list_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan list format (default output)"""
        # Create scan record
        scan = models.Scan(
            filename=filename,
            scan_type='port_scan',
            tool_name='masscan',
            created_at=datetime.utcnow()
        )
        
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        
        hosts_data = {}
        out_of_scope_count = 0
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse line format: "open tcp 80 1.2.3.4 1234567890"
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                try:
                    state = parts[0]  # open, closed, etc.
                    protocol = parts[1]  # tcp, udp
                    port_number = int(parts[2])
                    ip_address = parts[3]
                    
                    # Skip non-open ports for optimization (closed/filtered provide limited value)
                    if state not in ['open']:
                        continue
                    
                    # Check if IP is in scope
                    matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
                    
                    if matching_subnets:
                        # Create or get host record
                        if ip_address not in hosts_data:
                            host = models.Host(
                                scan_id=scan.id,
                                ip_address=ip_address,
                                state='up'
                            )
                            self.db.add(host)
                            self.db.flush()
                            hosts_data[ip_address] = host
                        else:
                            host = hosts_data[ip_address]
                        
                        # Add port information
                        port = models.Port(
                            host_id=host.id,
                            port_number=port_number,
                            protocol=protocol,
                            state=state
                        )
                        self.db.add(port)
                    else:
                        # Check if we already have this out-of-scope host
                        existing = None
                        for existing_host in self.db.query(models.OutOfScopeHost).filter(
                            models.OutOfScopeHost.scan_id == scan.id,
                            models.OutOfScopeHost.ip_address == ip_address
                        ).all():
                            existing = existing_host
                            break
                        
                        if existing:
                            # Add port to existing out-of-scope host
                            ports = existing.ports or {'masscan_ports': []}
                            if 'masscan_ports' not in ports:
                                ports['masscan_ports'] = []
                            ports['masscan_ports'].append({
                                'port': port_number,
                                'protocol': protocol,
                                'state': state
                            })
                            existing.ports = ports
                        else:
                            # Create new out-of-scope host
                            out_of_scope = models.OutOfScopeHost(
                                scan_id=scan.id,
                                ip_address=ip_address,
                                ports={'masscan_ports': [{
                                    'port': port_number,
                                    'protocol': protocol,
                                    'state': state
                                }]},
                                tool_source='masscan',
                                reason='IP address not found in any defined subnet scope'
                            )
                            self.db.add(out_of_scope)
                            out_of_scope_count += 1
                
                except (ValueError, IndexError) as e:
                    logger.warning(f"Error parsing Masscan line '{line}': {str(e)}")
                    continue
        
        # Correlate hosts to subnets
        try:
            mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
            logger.info(f"Created {mappings_created} host-subnet mappings for Masscan scan {scan.id}")
        except Exception as e:
            logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
        
        self.db.commit()
        
        logger.info(f"Processed {len(hosts_data)} in-scope hosts and {out_of_scope_count} out-of-scope hosts from Masscan list")
        return scan

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp from Masscan XML"""
        if not timestamp_str:
            return None
        try:
            return datetime.fromtimestamp(int(timestamp_str))
        except (ValueError, TypeError):
            return None