from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session
from app.db import models
from app.services.subnet_correlation import SubnetCorrelationService
import logging
import time
import re

logger = logging.getLogger(__name__)

class GnmapParser:
    def __init__(self, db: Session):
        self.db = db
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
        self.db.commit()
        self.db.refresh(scan)
        logger.info(f"Scan record created with ID: {scan.id}")
        
        # Parse hosts
        hosts_data = self._parse_hosts(lines)
        total_hosts = len(hosts_data)
        logger.info(f"Found {total_hosts} hosts to parse")
        
        # Process hosts with progress logging
        hosts_parsed = 0
        start_time = time.time()
        
        for i, host_data in enumerate(hosts_data, 1):
            if i % 100 == 0 or i == 1:
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                logger.info(f"Processing host {i}/{total_hosts} ({i/total_hosts*100:.1f}%) - Rate: {rate:.1f} hosts/sec")
            
            try:
                self._create_host_record(host_data, scan.id)
                hosts_parsed += 1
            except Exception as e:
                logger.warning(f"Failed to parse host {i}: {str(e)}")
        
        # Commit all parsed data at once
        logger.info(f"Committing all parsed data to database ({hosts_parsed} hosts processed)")
        self.db.commit()
        
        # Correlate hosts to subnets
        logger.info(f"Starting subnet correlation for scan {scan.id}")
        try:
            correlation_start = time.time()
            mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
            correlation_time = time.time() - correlation_start
            logger.info(f"Created {mappings_created} host-subnet mappings for scan {scan.id} in {correlation_time:.2f} seconds")
        except Exception as e:
            logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
            
        total_time = time.time() - start_time
        logger.info(f"Completed parsing {filename}: {hosts_parsed}/{total_hosts} hosts in {total_time:.2f} seconds")
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
        hosts_data = []
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if line.startswith('#') or not line:
                continue
                
            # Parse Host lines
            if line.startswith('Host:'):
                host_data = self._parse_host_line(line)
                if host_data:
                    hosts_data.append(host_data)
        
        return hosts_data

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
            
            # Skip hosts with no meaningful data (down hosts with no ports)
            if state == 'down' or (state not in ['up'] and not ports_data):
                return None
            
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

    def _create_host_record(self, host_data: Dict[str, Any], scan_id: int):
        """Create host and port records in the database"""
        # Create host record
        host = models.Host(
            scan_id=scan_id,
            ip_address=host_data['ip_address'],
            hostname=host_data.get('hostname'),
            state=host_data['state'],
            state_reason=host_data.get('state_reason', '')
        )
        
        self.db.add(host)
        self.db.flush()  # Get host ID without committing
        self.db.refresh(host)
        
        # Create port records
        for port_data in host_data.get('ports', []):
            port = models.Port(
                host_id=host.id,
                port_number=port_data['port_number'],
                protocol=port_data['protocol'],
                state=port_data['state'],
                service_name=port_data.get('service_name'),
                service_version=port_data.get('service_version')
            )
            self.db.add(port)