import xml.etree.ElementTree as ET
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session
from app.db import models
from app.services.subnet_correlation import SubnetCorrelationService
import logging
import time

logger = logging.getLogger(__name__)

class MasscanParser:
    def __init__(self, db: Session):
        self.db = db
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan output files (XML, JSON, or list format)"""
        start_time = time.time()
        logger.info(f"Starting Masscan parse of {filename}")
        
        try:
            if filename.lower().endswith('.xml'):
                result = self._parse_xml_file(file_path, filename)
            elif filename.lower().endswith('.json'):
                result = self._parse_json_file(file_path, filename)
            else:
                # Assume list format (default masscan output)
                result = self._parse_list_file(file_path, filename)
            
            elapsed_time = time.time() - start_time
            logger.info(f"Successfully parsed Masscan {filename} in {elapsed_time:.2f} seconds")
            return result
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Error parsing Masscan file {filename} after {elapsed_time:.2f} seconds: {str(e)}")
            raise

    def _parse_xml_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan XML output using single database transaction"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Parse and validate all data before database operations
        processed_hosts = {}
        out_of_scope_entries = []
        
        for host_elem in root.findall('host'):
            # Get IP address
            addr_elem = host_elem.find('address')
            if addr_elem is None:
                continue
                
            ip_address = addr_elem.get('addr')
            if not ip_address:
                continue
            
            # Get host state
            status_elem = host_elem.find('status')
            state = status_elem.get('state') if status_elem is not None else 'unknown'
            
            # Skip hosts that are down or filtered - they provide no useful information
            if state in ['down', 'filtered']:
                continue
            
            # Check if host has any meaningful data (open ports)
            has_meaningful_data = False
            host_ports = []
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    try:
                        port_number = int(port_elem.get('portid'))
                        protocol = port_elem.get('protocol')
                        state_elem = port_elem.find('state')
                        port_state = state_elem.get('state') if state_elem is not None else 'unknown'
                        
                        port_info = {
                            'port_number': port_number,
                            'protocol': protocol,
                            'state': port_state
                        }
                        host_ports.append(port_info)
                        
                        if port_state == 'open':
                            has_meaningful_data = True
                    except (ValueError, AttributeError) as e:
                        logger.warning(f"Error parsing port for host {ip_address}: {str(e)}")
                        continue
            
            # Skip hosts with no meaningful data
            if not has_meaningful_data:
                continue
            
            # Check if IP is in scope
            matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
            
            if matching_subnets:
                # Store in-scope host data
                processed_hosts[ip_address] = {
                    'state': state,
                    'ports': host_ports
                }
            else:
                # Store out-of-scope host data
                ports_data = [{'port': p['port_number'], 'protocol': p['protocol'], 'state': p['state']} 
                             for p in host_ports]
                out_of_scope_info = {
                    'ip_address': ip_address,
                    'ports': {'masscan_ports': ports_data},
                    'tool_source': 'masscan',
                    'reason': 'IP address not found in any defined subnet scope'
                }
                out_of_scope_entries.append(out_of_scope_info)
        
        # Now create all database records in a single transaction
        try:
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
            self.db.flush()  # Get scan ID without committing
            
            # Bulk create host records
            hosts_data = []
            for ip_address, host_data in processed_hosts.items():
                hosts_data.append({
                    'scan_id': scan.id,
                    'ip_address': ip_address,
                    'state': host_data['state']
                })
            
            if hosts_data:
                self.db.bulk_insert_mappings(models.Host, hosts_data)
                self.db.flush()
                
                # Get host ID mappings
                host_id_map = {}
                hosts = self.db.query(models.Host).filter(models.Host.scan_id == scan.id).all()
                for host in hosts:
                    host_id_map[host.ip_address] = host.id
                
                # Bulk create port records
                ports_data = []
                for ip_address, host_data in processed_hosts.items():
                    host_id = host_id_map[ip_address]
                    for port_info in host_data['ports']:
                        ports_data.append({
                            'host_id': host_id,
                            'port_number': port_info['port_number'],
                            'protocol': port_info['protocol'],
                            'state': port_info['state']
                        })
                
                if ports_data:
                    self.db.bulk_insert_mappings(models.Port, ports_data)
            
            # Bulk create out-of-scope records
            if out_of_scope_entries:
                oos_data = []
                for oos_info in out_of_scope_entries:
                    oos_data.append({
                        'scan_id': scan.id,
                        **oos_info
                    })
                self.db.bulk_insert_mappings(models.OutOfScopeHost, oos_data)
            
            # Correlate hosts to subnets
            mappings_created = 0
            try:
                mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
                logger.info(f"Created {mappings_created} host-subnet mappings for Masscan scan {scan.id}")
            except Exception as e:
                logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
            
            # Commit all changes as single transaction
            self.db.commit()
            
            logger.info(f"Processed {len(processed_hosts)} in-scope hosts and {len(out_of_scope_entries)} out-of-scope hosts from Masscan XML")
            return scan
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Database transaction failed, rolling back: {str(e)}")
            raise

    def _parse_json_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan JSON output using single database transaction"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Parse and validate all data before database operations
        processed_hosts = {}
        out_of_scope_entries = []
        
        for entry in data:
            ip_address = entry.get('ip')
            if not ip_address:
                continue
            
            # Extract port data with validation
            host_ports = []
            has_meaningful_data = False
            
            for port_info in entry.get('ports', []):
                try:
                    port_number = port_info.get('port')
                    protocol = port_info.get('proto', 'tcp')
                    port_status = port_info.get('status', 'open')
                    
                    if port_number is None:
                        continue
                        
                    port_data = {
                        'port_number': int(port_number),
                        'protocol': protocol,
                        'state': port_status
                    }
                    host_ports.append(port_data)
                    
                    if port_status == 'open':
                        has_meaningful_data = True
                        
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error parsing port data for host {ip_address}: {str(e)}")
                    continue
            
            # Skip hosts with no meaningful data
            if not has_meaningful_data:
                continue
            
            # Check if IP is in scope
            matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
            
            if matching_subnets:
                # Store or merge in-scope host data
                if ip_address in processed_hosts:
                    processed_hosts[ip_address]['ports'].extend(host_ports)
                else:
                    processed_hosts[ip_address] = {
                        'state': 'up',
                        'ports': host_ports
                    }
            else:
                # Store out-of-scope host data
                out_of_scope_info = {
                    'ip_address': ip_address,
                    'ports': {'masscan_ports': entry.get('ports', [])},
                    'tool_source': 'masscan',
                    'reason': 'IP address not found in any defined subnet scope'
                }
                out_of_scope_entries.append(out_of_scope_info)
        
        # Now create all database records in a single transaction
        try:
            # Create scan record
            scan = models.Scan(
                filename=filename,
                scan_type='port_scan',
                tool_name='masscan',
                created_at=datetime.utcnow()
            )
            self.db.add(scan)
            self.db.flush()  # Get scan ID without committing
            
            # Bulk create host and port records
            hosts_data = []
            for ip_address, host_data in processed_hosts.items():
                hosts_data.append({
                    'scan_id': scan.id,
                    'ip_address': ip_address,
                    'state': host_data['state']
                })
            
            if hosts_data:
                self.db.bulk_insert_mappings(models.Host, hosts_data)
                self.db.flush()
                
                # Get host ID mappings
                host_id_map = {}
                hosts = self.db.query(models.Host).filter(models.Host.scan_id == scan.id).all()
                for host in hosts:
                    host_id_map[host.ip_address] = host.id
                
                # Bulk create port records
                ports_data = []
                for ip_address, host_data in processed_hosts.items():
                    host_id = host_id_map[ip_address]
                    for port_info in host_data['ports']:
                        ports_data.append({
                            'host_id': host_id,
                            'port_number': port_info['port_number'],
                            'protocol': port_info['protocol'],
                            'state': port_info['state']
                        })
                
                if ports_data:
                    self.db.bulk_insert_mappings(models.Port, ports_data)
            
            # Bulk create out-of-scope records
            if out_of_scope_entries:
                oos_data = []
                for oos_info in out_of_scope_entries:
                    oos_data.append({
                        'scan_id': scan.id,
                        **oos_info
                    })
                self.db.bulk_insert_mappings(models.OutOfScopeHost, oos_data)
            
            # Correlate hosts to subnets
            mappings_created = 0
            try:
                mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
                logger.info(f"Created {mappings_created} host-subnet mappings for Masscan scan {scan.id}")
            except Exception as e:
                logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
            
            # Commit all changes as single transaction
            self.db.commit()
            
            logger.info(f"Processed {len(processed_hosts)} in-scope hosts and {len(out_of_scope_entries)} out-of-scope hosts from Masscan JSON")
            return scan
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Database transaction failed, rolling back: {str(e)}")
            raise

    def _parse_list_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Masscan list format (default output) using single database transaction"""
        # Parse and validate all data before database operations
        processed_hosts = {}
        out_of_scope_entries = []
        
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
                    
                    # Prepare port data
                    port_info = {
                        'port_number': port_number,
                        'protocol': protocol,
                        'state': state
                    }
                    
                    # Check if IP is in scope
                    matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
                    
                    if matching_subnets:
                        # Store or merge in-scope host data
                        if ip_address in processed_hosts:
                            processed_hosts[ip_address]['ports'].append(port_info)
                        else:
                            processed_hosts[ip_address] = {
                                'state': 'up',
                                'ports': [port_info]
                            }
                    else:
                        # Store out-of-scope host data
                        existing_oos = None
                        for oos_entry in out_of_scope_entries:
                            if oos_entry['ip_address'] == ip_address:
                                existing_oos = oos_entry
                                break
                        
                        if existing_oos:
                            # Add port to existing out-of-scope host
                            existing_oos['ports']['masscan_ports'].append({
                                'port': port_number,
                                'protocol': protocol,
                                'state': state
                            })
                        else:
                            # Create new out-of-scope host entry
                            out_of_scope_info = {
                                'ip_address': ip_address,
                                'ports': {'masscan_ports': [{
                                    'port': port_number,
                                    'protocol': protocol,
                                    'state': state
                                }]},
                                'tool_source': 'masscan',
                                'reason': 'IP address not found in any defined subnet scope'
                            }
                            out_of_scope_entries.append(out_of_scope_info)
                
                except (ValueError, IndexError) as e:
                    logger.warning(f"Error parsing Masscan line '{line}': {str(e)}")
                    continue
        
        # Now create all database records in a single transaction
        try:
            # Create scan record
            scan = models.Scan(
                filename=filename,
                scan_type='port_scan',
                tool_name='masscan',
                created_at=datetime.utcnow()
            )
            self.db.add(scan)
            self.db.flush()  # Get scan ID without committing
            
            # Bulk create host and port records
            hosts_data = []
            for ip_address, host_data in processed_hosts.items():
                hosts_data.append({
                    'scan_id': scan.id,
                    'ip_address': ip_address,
                    'state': host_data['state']
                })
            
            if hosts_data:
                self.db.bulk_insert_mappings(models.Host, hosts_data)
                self.db.flush()
                
                # Get host ID mappings
                host_id_map = {}
                hosts = self.db.query(models.Host).filter(models.Host.scan_id == scan.id).all()
                for host in hosts:
                    host_id_map[host.ip_address] = host.id
                
                # Bulk create port records
                ports_data = []
                for ip_address, host_data in processed_hosts.items():
                    host_id = host_id_map[ip_address]
                    for port_info in host_data['ports']:
                        ports_data.append({
                            'host_id': host_id,
                            'port_number': port_info['port_number'],
                            'protocol': port_info['protocol'],
                            'state': port_info['state']
                        })
                
                if ports_data:
                    self.db.bulk_insert_mappings(models.Port, ports_data)
            
            # Bulk create out-of-scope records
            if out_of_scope_entries:
                oos_data = []
                for oos_info in out_of_scope_entries:
                    oos_data.append({
                        'scan_id': scan.id,
                        **oos_info
                    })
                self.db.bulk_insert_mappings(models.OutOfScopeHost, oos_data)
            
            # Correlate hosts to subnets
            mappings_created = 0
            try:
                mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
                logger.info(f"Created {mappings_created} host-subnet mappings for Masscan scan {scan.id}")
            except Exception as e:
                logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
            
            # Commit all changes as single transaction
            self.db.commit()
            
            logger.info(f"Processed {len(processed_hosts)} in-scope hosts and {len(out_of_scope_entries)} out-of-scope hosts from Masscan list")
            return scan
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Database transaction failed, rolling back: {str(e)}")
            raise

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp from Masscan XML"""
        if not timestamp_str:
            return None
        try:
            return datetime.fromtimestamp(int(timestamp_str))
        except (ValueError, TypeError):
            return None