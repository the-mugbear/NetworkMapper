from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session
from app.db import models
from app.services.host_deduplication_service import HostDeduplicationService
from app.services.subnet_correlation import SubnetCorrelationService
import logging
import time
import re

logger = logging.getLogger(__name__)

class GnmapParser:
    def __init__(self, db: Session):
        self.db = db
        self.dedup_service = HostDeduplicationService(db)
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        start_time = time.time()
        logger.info(f"Starting parse of .gnmap file {filename}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                logger.info(f"Loaded .gnmap file {filename}")
                
            result = self._parse_gnmap_content(content, filename)
            elapsed_time = time.time() - start_time
            logger.info(f"Successfully parsed {filename} in {elapsed_time:.2f} seconds")
            return result
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Error parsing .gnmap file {filename} after {elapsed_time:.2f} seconds: {str(e)}")
            raise

    def _parse_gnmap_content(self, content: str, filename: str) -> models.Scan:
        logger.info(f"Creating scan record for {filename}")
        
        # Create scan record
        scan = models.Scan(
            filename=filename,
            tool_name='nmap',
            scan_type='nmap_gnmap'
        )
        
        # Parse the content to extract basic scan info
        lines = content.strip().split('\n')
        scan_info = self._extract_scan_info(lines)
        
        # Set scan metadata
        if 'command' in scan_info:
            scan.command_line = scan_info['command']
        if 'version' in scan_info:
            scan.version = scan_info['version']
        if 'start_time' in scan_info:
            scan.start_time = scan_info['start_time']
        if 'end_time' in scan_info:
            scan.end_time = scan_info['end_time']
            
        # Save scan to get ID
        logger.info(f"Saving initial scan record to database")
        self.db.add(scan)
        self.db.flush()
        scan_id = scan.id
        
        # Parse hosts
        hosts_data = self._parse_hosts(lines)
        total_hosts = len(hosts_data)
        logger.info(f"Found {total_hosts} hosts to parse")
        
        # Process hosts with deduplication
        hosts_processed = 0
        for host_data in hosts_data:
            try:
                self._process_host_with_deduplication(host_data, scan_id)
                hosts_processed += 1
                
                if hosts_processed % 100 == 0:
                    logger.info(f"Processed {hosts_processed} hosts")
                    
            except Exception as e:
                logger.error(f"Error processing host {host_data.get('ip_address', 'unknown')}: {e}")
                continue
        
        # Correlate hosts to subnets
        try:
            logger.info(f"Starting subnet correlation for scan {scan_id}")
            hosts_correlated = self.correlation_service.batch_correlate_scan_hosts_to_subnets(scan_id)
            logger.info(f"Correlated {hosts_correlated} hosts to subnets")
        except Exception as e:
            logger.error(f"Error in subnet correlation: {e}")
            # Continue parsing even if correlation fails
        
        logger.info(f"Completed parsing {filename}: {hosts_processed}/{total_hosts} hosts processed")
        return scan

    def _extract_scan_info(self, lines: List[str]) -> Dict[str, Any]:
        """Extract scan metadata from .gnmap file header and footer"""
        scan_info = {}
        
        for line in lines:
            line = line.strip()
            
            # Parse command line from first comment
            if line.startswith('# Nmap') and 'command' not in scan_info:
                # Extract command line from comment
                match = re.search(r'# Nmap (.+?) scan initiated', line)
                if match:
                    scan_info['version'] = match.group(1).split()[0]
                    
                # Try to extract full command from the line
                if ' done at ' in line:
                    continue  # This is the end line
                else:
                    # Extract command portion
                    cmd_match = re.search(r'# (.+)', line)
                    if cmd_match:
                        scan_info['command'] = cmd_match.group(1)
            
            # Parse start time
            if 'scan initiated' in line:
                time_match = re.search(r'scan initiated (.+)$', line)
                if time_match:
                    try:
                        scan_info['start_time'] = datetime.strptime(time_match.group(1), '%a %b %d %H:%M:%S %Y')
                    except ValueError:
                        pass
            
            # Parse end time
            if 'done at' in line:
                time_match = re.search(r'done at (.+)$', line)
                if time_match:
                    try:
                        scan_info['end_time'] = datetime.strptime(time_match.group(1), '%a %b %d %H:%M:%S %Y')
                    except ValueError:
                        pass
        
        return scan_info

    def _parse_hosts(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parse host data from .gnmap lines"""
        hosts_data = {}  # Use dict to merge status and port lines by IP
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if line.startswith('#') or not line or line.startswith('Nmap') or line.startswith('Ports scanned'):
                continue
                
            # Parse Host lines
            if line.startswith('Host:'):
                host_data = self._parse_host_line(line)
                if host_data:
                    ip = host_data['ip_address']
                    
                    # Merge with existing host data or create new
                    if ip in hosts_data:
                        # Merge data - prefer non-empty values
                        existing = hosts_data[ip]
                        existing['hostname'] = existing.get('hostname') or host_data.get('hostname')
                        # Prefer actual state over 'unknown'
                        if host_data.get('state') and host_data['state'] != 'unknown':
                            existing['state'] = host_data['state']
                        elif not existing.get('state') or existing['state'] == 'unknown':
                            existing['state'] = host_data.get('state', 'unknown')
                        existing['state_reason'] = host_data.get('state_reason') or existing.get('state_reason', '')
                        if host_data.get('ports'):
                            existing['ports'] = host_data['ports']
                    else:
                        hosts_data[ip] = host_data
        
        # Convert dict back to list and filter out down hosts with no ports
        result = []
        for host_data in hosts_data.values():
            # Only include hosts that are up or have port data
            if host_data.get('state') == 'up' or host_data.get('ports'):
                result.append(host_data)
        
        return result

    def _parse_host_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single Host: line from .gnmap format"""
        try:
            # .gnmap format: Host: <ip> (<hostname>)	Status: <state>	Ports: <port_info>
            parts = line.split('\t')
            
            if len(parts) < 2:
                return None
            
            # Parse host info (first part)
            host_part = parts[0]  # "Host: 192.168.1.1 (hostname)"
            host_match = re.match(r'Host:\s+([^\s]+)(?:\s+\(([^)]+)\))?', host_part)
            
            if not host_match:
                return None
                
            ip_address = host_match.group(1)
            hostname = host_match.group(2) if host_match.group(2) else None
            
            # Parse status
            state = 'unknown'
            state_reason = ''
            for part in parts:
                if part.startswith('Status:'):
                    status_match = re.search(r'Status:\s+(\w+)', part)
                    if status_match:
                        state = status_match.group(1)
            
            # Parse ports
            ports_data = []
            for part in parts:
                if part.startswith('Ports:'):
                    ports_info = part[6:].strip()  # Remove "Ports:"
                    if ports_info:
                        ports_data = self._parse_ports_info(ports_info)
            
            # Don't skip here - let the merge logic handle filtering
            
            return {
                'ip_address': ip_address,
                'hostname': hostname,
                'state': state,
                'state_reason': state_reason,
                'ports': ports_data
            }
            
        except Exception as e:
            logger.warning(f"Failed to parse host line: {line[:100]}... Error: {str(e)}")
            return None

    def _parse_ports_info(self, ports_info: str) -> List[Dict[str, Any]]:
        """Parse port information from .gnmap format"""
        ports_data = []
        
        # .gnmap ports format: port/state/protocol/owner/service/rpc/version, port/state/...
        if not ports_info or ports_info.strip() == '':
            return ports_data
            
        port_entries = ports_info.split(', ')
        
        for entry in port_entries:
            try:
                # Split by / - format: port/state/protocol/owner/service/rpc/version
                fields = entry.split('/')
                if len(fields) < 3:
                    continue
                    
                port_number = int(fields[0])
                state = fields[1]
                protocol = fields[2]
                
                # Extract additional service info if available
                service_name = fields[4] if len(fields) > 4 and fields[4] else None
                service_version = fields[6] if len(fields) > 6 and fields[6] else None
                
                # Only include meaningful ports (open, closed with some data)
                if state in ['open'] or (state in ['closed', 'filtered'] and service_name):
                    port_data = {
                        'port_number': port_number,
                        'protocol': protocol,
                        'state': state,
                        'service_name': service_name,
                        'service_version': service_version
                    }
                    ports_data.append(port_data)
                    
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse port entry: {entry} - {str(e)}")
                continue
        
        return ports_data

    def _process_host_with_deduplication(self, host_data: Dict[str, Any], scan_id: int):
        """Process a single host using deduplication service"""
        ip_address = host_data.get('ip_address')
        if not ip_address:
            logger.warning("Host without IP address, skipping")
            return

        # Extract host metadata for deduplication service
        host_metadata = {
            'hostname': host_data.get('hostname'),
            'state': host_data.get('state'),
            'state_reason': host_data.get('state_reason')
        }

        # Find or create deduplicated host
        host = self.dedup_service.find_or_create_host(ip_address, scan_id, host_metadata)

        # Process ports
        for port_data in host_data.get('ports', []):
            # Extract port information
            port_info = {
                'port_number': port_data.get('port_number'),
                'protocol': port_data.get('protocol', 'tcp'),
                'state': port_data.get('state'),
                'service_name': port_data.get('service_name'),
                'service_version': port_data.get('service_version')
            }
            
            # Find or create deduplicated port
            self.dedup_service.find_or_create_port(host.id, scan_id, port_info)