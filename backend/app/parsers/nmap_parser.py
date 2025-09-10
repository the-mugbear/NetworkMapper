from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from lxml import etree
from sqlalchemy.orm import Session
from app.db import models
from app.services.subnet_correlation import SubnetCorrelationService
import logging
import time

logger = logging.getLogger(__name__)

class NmapXMLParser:
    def __init__(self, db: Session):
        self.db = db
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        start_time = time.time()
        logger.info(f"Starting parse of {filename}")
        
        try:
            with open(file_path, 'rb') as f:
                logger.info(f"Loading XML tree for {filename}")
                tree = etree.parse(f)
                root = tree.getroot()
                logger.info(f"XML tree loaded successfully for {filename}")
                
            result = self._parse_root(root, filename)
            elapsed_time = time.time() - start_time
            logger.info(f"Successfully parsed {filename} in {elapsed_time:.2f} seconds")
            return result
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Error parsing XML file {filename} after {elapsed_time:.2f} seconds: {str(e)}")
            raise

    def _parse_root(self, root: etree.Element, filename: str) -> models.Scan:
        logger.info(f"Creating scan record for {filename}")
        
        # Create scan record
        scan = models.Scan(
            filename=filename,
            tool_name='nmap',
            version=root.get('version'),
            xml_output_version=root.get('xmloutputversion'),
        )
        
        # Parse scan info
        scaninfo_elem = root.find('scaninfo')
        if scaninfo_elem is not None:
            scan.scan_type = scaninfo_elem.get('type')
        
        # Parse run stats for timing
        runstats = root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                try:
                    scan.end_time = datetime.fromtimestamp(int(finished.get('time', '0')))
                except (ValueError, TypeError):
                    pass
        
        # Parse command line arguments
        scan.command_line = root.get('args', '')
        
        # Save scan to get ID - this is the only commit until the end
        logger.info(f"Saving initial scan record to database")
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        logger.info(f"Scan record created with ID: {scan.id}")
        
        # Parse scan info details
        logger.info(f"Parsing scan info details")
        self._parse_scan_info(root, scan.id)
        
        # Pre-filter hosts for meaningful data to reduce processing
        logger.info("Pre-filtering hosts for meaningful data...")
        host_elements = root.findall('host')
        meaningful_hosts = self._filter_meaningful_hosts(host_elements)
        total_hosts = len(host_elements)
        meaningful_count = len(meaningful_hosts)
        logger.info(f"Found {meaningful_count}/{total_hosts} meaningful hosts to parse")
        
        # Batch parse all hosts and related data
        start_time = time.time()
        hosts_data, ports_data, scripts_data, host_scripts_data = self._batch_parse_hosts(
            meaningful_hosts, scan.id
        )
        
        # Bulk insert all data
        logger.info("Performing bulk database insertions...")
        bulk_start = time.time()
        
        # Insert hosts
        if hosts_data:
            self.db.bulk_insert_mappings(models.Host, hosts_data)
            self.db.flush()
            
        # Get host IDs for foreign key relationships
        host_id_map = self._build_host_id_map(scan.id, hosts_data)
        
        # Update ports data with host IDs
        for port_data in ports_data:
            port_data['host_id'] = host_id_map[port_data['ip_address']]
        
        # Insert ports
        if ports_data:
            self.db.bulk_insert_mappings(models.Port, ports_data)
            self.db.flush()
            
        # Get port IDs for script relationships
        port_id_map = self._build_port_id_map(host_id_map, ports_data)
        
        # Update scripts data with port IDs
        for script_data in scripts_data:
            key = (script_data['ip_address'], script_data['port_number'], script_data['protocol'])
            if key in port_id_map:
                script_data['port_id'] = port_id_map[key]
                del script_data['ip_address']
                del script_data['port_number'] 
                del script_data['protocol']
        
        # Update host scripts data with host IDs
        for host_script_data in host_scripts_data:
            host_script_data['host_id'] = host_id_map[host_script_data['ip_address']]
            del host_script_data['ip_address']
        
        # Insert scripts
        if scripts_data:
            valid_scripts = [s for s in scripts_data if 'port_id' in s]
            if valid_scripts:
                self.db.bulk_insert_mappings(models.Script, valid_scripts)
                
        if host_scripts_data:
            self.db.bulk_insert_mappings(models.HostScript, host_scripts_data)
            
        bulk_time = time.time() - bulk_start
        logger.info(f"Bulk insertions completed in {bulk_time:.2f} seconds")
        
        # Single commit for all data
        self.db.commit()
        
        # Batch correlate all hosts from this scan to subnets
        logger.info(f"Starting batch subnet correlation for scan {scan.id}")
        try:
            correlation_start = time.time()
            mappings_created = self.correlation_service.batch_correlate_scan_hosts_to_subnets(scan.id)
            correlation_time = time.time() - correlation_start
            logger.info(f"Created {mappings_created} host-subnet mappings for scan {scan.id} in {correlation_time:.2f} seconds")
        except Exception as e:
            logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
            # Fallback to individual correlation if batch fails
            try:
                mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
                logger.info(f"Fallback: Created {mappings_created} mappings using individual correlation")
            except Exception as e2:
                logger.error(f"Both batch and individual correlation failed: {str(e2)}")
            
        total_time = time.time() - start_time
        logger.info(f"Completed parsing {filename}: {meaningful_count} hosts in {total_time:.2f} seconds")
        return scan

    def _parse_scan_info(self, root: etree.Element, scan_id: int):
        scaninfo_elem = root.find('scaninfo')
        if scaninfo_elem is not None:
            scan_info = models.ScanInfo(
                scan_id=scan_id,
                type=scaninfo_elem.get('type'),
                protocol=scaninfo_elem.get('protocol'),
                numservices=int(scaninfo_elem.get('numservices', 0)),
                services=scaninfo_elem.get('services', '')
            )
            self.db.add(scan_info)

    def _parse_host(self, host_elem: etree.Element, scan_id: int):
        # Get IP address
        address_elem = host_elem.find('address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host_elem.find('address[@addrtype="ipv6"]')
        
        if address_elem is None:
            return
            
        ip_address = address_elem.get('addr')
        
        # Get host state
        status_elem = host_elem.find('status')
        state = status_elem.get('state') if status_elem is not None else 'unknown'
        state_reason = status_elem.get('reason') if status_elem is not None else ''
        
        # Skip hosts that are down or filtered - they provide no useful information
        if state in ['down', 'filtered']:
            return
            
        # Check if host has any meaningful data (open/closed ports, host scripts, or OS info)
        has_meaningful_data = False
        
        # Check for ports with useful information
        ports_elem = host_elem.find('ports')
        open_ports = []
        closed_ports = []
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                port_state_elem = port_elem.find('state')
                if port_state_elem is not None:
                    port_state = port_state_elem.get('state')
                    if port_state == 'open':
                        open_ports.append(port_elem)
                        has_meaningful_data = True
                    elif port_state in ['closed', 'unfiltered']:
                        closed_ports.append(port_elem)
                        # Only consider closed ports meaningful if there are many (indicates active host)
                        if len(closed_ports) >= 3:
                            has_meaningful_data = True
        
        # Check for host scripts (always meaningful)
        hostscript_elem = host_elem.find('hostscript')
        if hostscript_elem is not None and len(hostscript_elem.findall('script')) > 0:
            has_meaningful_data = True
        
        # Check for OS detection (always meaningful)
        os_elem = host_elem.find('os')
        if os_elem is not None and len(os_elem.findall('osmatch')) > 0:
            has_meaningful_data = True
        
        # Skip hosts with no meaningful data (no open ports, no scripts, no OS info)
        if not has_meaningful_data and state not in ['up']:
            return
        
        # For 'up' hosts with no meaningful data, only keep if they have a hostname or are explicitly up
        if not has_meaningful_data and state == 'up':
            hostnames_elem = host_elem.find('hostnames')
            has_hostname = (hostnames_elem is not None and 
                          hostnames_elem.find('hostname') is not None)
            if not has_hostname:
                return
        
        # Get hostname
        hostname = None
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')
        
        # Parse OS detection
        os_info = self._parse_os(host_elem)
        
        # Create host record (only for meaningful hosts)
        host = models.Host(
            scan_id=scan_id,
            ip_address=ip_address,
            hostname=hostname,
            state=state,
            state_reason=state_reason,
            **os_info
        )
        
        self.db.add(host)
        # Note: No commit here - we'll commit all data at the end for better performance
        self.db.flush()  # Get the host ID without committing
        self.db.refresh(host)
        
        # Parse ports (only open and meaningful closed ports)
        if ports_elem is not None:
            # Parse open ports (always included)
            for port_elem in open_ports:
                self._parse_port(port_elem, host.id)
            
            # Parse closed ports only if there are open ports or many closed ports
            if len(open_ports) > 0 or len(closed_ports) >= 5:
                for port_elem in closed_ports[:20]:  # Limit closed ports to reduce noise
                    self._parse_port(port_elem, host.id)
        
        # Parse host scripts
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall('script'):
                self._parse_host_script(script_elem, host.id)

    def _parse_os(self, host_elem: etree.Element) -> Dict[str, Any]:
        os_info = {}
        os_elem = host_elem.find('os')
        
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                os_info['os_name'] = osmatch.get('name')
                os_info['os_accuracy'] = int(osmatch.get('accuracy', 0))
                
                osclass = osmatch.find('osclass')
                if osclass is not None:
                    os_info['os_type'] = osclass.get('type')
                    os_info['os_vendor'] = osclass.get('vendor')
                    os_info['os_family'] = osclass.get('osfamily')
                    os_info['os_generation'] = osclass.get('osgen')
        
        return os_info

    def _parse_port(self, port_elem: etree.Element, host_id: int):
        port_number = int(port_elem.get('portid'))
        protocol = port_elem.get('protocol')
        
        # Get port state
        state_elem = port_elem.find('state')
        state = state_elem.get('state') if state_elem is not None else 'unknown'
        reason = state_elem.get('reason') if state_elem is not None else ''
        
        # Get service info
        service_info = self._parse_service(port_elem)
        
        # Create port record
        port = models.Port(
            host_id=host_id,
            port_number=port_number,
            protocol=protocol,
            state=state,
            reason=reason,
            **service_info
        )
        
        self.db.add(port)
        # Note: No commit here - we'll commit all data at the end for better performance  
        self.db.flush()  # Get the port ID without committing
        self.db.refresh(port)
        
        # Parse port scripts
        for script_elem in port_elem.findall('script'):
            self._parse_script(script_elem, port.id)

    def _parse_service(self, port_elem: etree.Element) -> Dict[str, Any]:
        service_info = {}
        service_elem = port_elem.find('service')
        
        if service_elem is not None:
            service_info['service_name'] = service_elem.get('name')
            service_info['service_product'] = service_elem.get('product')
            service_info['service_version'] = service_elem.get('version')
            service_info['service_extrainfo'] = service_elem.get('extrainfo')
            service_info['service_method'] = service_elem.get('method')
            
            conf = service_elem.get('conf')
            if conf:
                service_info['service_conf'] = int(conf)
        
        return service_info

    def _parse_script(self, script_elem: etree.Element, port_id: int):
        script = models.Script(
            port_id=port_id,
            script_id=script_elem.get('id'),
            output=script_elem.get('output', '')
        )
        self.db.add(script)

    def _parse_host_script(self, script_elem: etree.Element, host_id: int):
        host_script = models.HostScript(
            host_id=host_id,
            script_id=script_elem.get('id'),
            output=script_elem.get('output', '')
        )
        self.db.add(host_script)

    def _filter_meaningful_hosts(self, host_elements: List[etree.Element]) -> List[etree.Element]:
        """Pre-filter hosts to only include those with meaningful data."""
        meaningful_hosts = []
        
        for host_elem in host_elements:
            # Quick state check - skip down/filtered hosts immediately
            status_elem = host_elem.find('status')
            if status_elem is not None:
                state = status_elem.get('state')
                if state in ['down', 'filtered']:
                    continue
            
            # Quick meaningful data check
            has_meaningful_data = False
            
            # Check for open ports
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    state_elem = port_elem.find('state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        has_meaningful_data = True
                        break
                        
            # Check for host scripts
            if not has_meaningful_data:
                hostscript_elem = host_elem.find('hostscript')
                if hostscript_elem is not None and len(hostscript_elem.findall('script')) > 0:
                    has_meaningful_data = True
            
            # Check for OS detection
            if not has_meaningful_data:
                os_elem = host_elem.find('os')
                if os_elem is not None and len(os_elem.findall('osmatch')) > 0:
                    has_meaningful_data = True
            
            # For 'up' hosts without meaningful data, check for hostname
            if not has_meaningful_data and status_elem is not None:
                if status_elem.get('state') == 'up':
                    hostnames_elem = host_elem.find('hostnames')
                    if (hostnames_elem is not None and 
                        hostnames_elem.find('hostname') is not None):
                        has_meaningful_data = True
            
            if has_meaningful_data:
                meaningful_hosts.append(host_elem)
                
        return meaningful_hosts

    def _batch_parse_hosts(self, host_elements: List[etree.Element], scan_id: int) -> Tuple[List[Dict], List[Dict], List[Dict], List[Dict]]:
        """Parse all hosts and return data structures for bulk insertion."""
        hosts_data = []
        ports_data = []
        scripts_data = []
        host_scripts_data = []
        
        for host_elem in host_elements:
            # Get IP address
            address_elem = host_elem.find('address[@addrtype="ipv4"]')
            if address_elem is None:
                address_elem = host_elem.find('address[@addrtype="ipv6"]')
            
            if address_elem is None:
                continue
                
            ip_address = address_elem.get('addr')
            
            # Get host state
            status_elem = host_elem.find('status')
            state = status_elem.get('state') if status_elem is not None else 'unknown'
            state_reason = status_elem.get('reason') if status_elem is not None else ''
            
            # Get hostname
            hostname = None
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')
            
            # Parse OS detection
            os_info = self._parse_os(host_elem)
            
            # Create host data
            host_data = {
                'scan_id': scan_id,
                'ip_address': ip_address,
                'hostname': hostname,
                'state': state,
                'state_reason': state_reason,
                **os_info
            }
            hosts_data.append(host_data)
            
            # Parse ports in single pass
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                open_ports, closed_ports = self._analyze_ports_single_pass(ports_elem)
                
                # Process open ports (always included)
                for port_data in open_ports:
                    port_data['ip_address'] = ip_address  # For ID mapping later
                    ports_data.append(port_data)
                    
                    # Parse port scripts
                    for port_elem in ports_elem.findall('port'):
                        if (int(port_elem.get('portid')) == port_data['port_number'] and 
                            port_elem.get('protocol') == port_data['protocol']):
                            for script_elem in port_elem.findall('script'):
                                script_data = {
                                    'ip_address': ip_address,
                                    'port_number': port_data['port_number'],
                                    'protocol': port_data['protocol'],
                                    'script_id': script_elem.get('id'),
                                    'output': script_elem.get('output', '')
                                }
                                scripts_data.append(script_data)
                            break
                
                # Process meaningful closed ports
                if len(open_ports) > 0 or len(closed_ports) >= 5:
                    for port_data in closed_ports[:20]:  # Limit to reduce noise
                        port_data['ip_address'] = ip_address
                        ports_data.append(port_data)
            
            # Parse host scripts
            hostscript_elem = host_elem.find('hostscript')
            if hostscript_elem is not None:
                for script_elem in hostscript_elem.findall('script'):
                    host_script_data = {
                        'ip_address': ip_address,
                        'script_id': script_elem.get('id'),
                        'output': script_elem.get('output', '')
                    }
                    host_scripts_data.append(host_script_data)
        
        return hosts_data, ports_data, scripts_data, host_scripts_data

    def _analyze_ports_single_pass(self, ports_elem: etree.Element) -> Tuple[List[Dict], List[Dict]]:
        """Analyze ports in a single pass and return open/closed port data."""
        open_ports = []
        closed_ports = []
        
        for port_elem in ports_elem.findall('port'):
            port_number = int(port_elem.get('portid'))
            protocol = port_elem.get('protocol')
            
            # Get port state
            state_elem = port_elem.find('state')
            state = state_elem.get('state') if state_elem is not None else 'unknown'
            reason = state_elem.get('reason') if state_elem is not None else ''
            
            # Get service info
            service_info = self._parse_service(port_elem)
            
            # Create port data
            port_data = {
                'port_number': port_number,
                'protocol': protocol,
                'state': state,
                'reason': reason,
                **service_info
            }
            
            if state == 'open':
                open_ports.append(port_data)
            elif state in ['closed', 'unfiltered']:
                closed_ports.append(port_data)
                
        return open_ports, closed_ports

    def _build_host_id_map(self, scan_id: int, hosts_data: List[Dict]) -> Dict[str, int]:
        """Build a mapping from IP address to host ID after insertion."""
        host_id_map = {}
        hosts = self.db.query(models.Host).filter(models.Host.scan_id == scan_id).all()
        for host in hosts:
            host_id_map[host.ip_address] = host.id
        return host_id_map

    def _build_port_id_map(self, host_id_map: Dict[str, int], ports_data: List[Dict]) -> Dict[Tuple, int]:
        """Build a mapping from (ip, port, protocol) to port ID after insertion."""
        port_id_map = {}
        for ip_address, host_id in host_id_map.items():
            ports = self.db.query(models.Port).filter(models.Port.host_id == host_id).all()
            for port in ports:
                key = (ip_address, port.port_number, port.protocol)
                port_id_map[key] = port.id
        return port_id_map