"""
Nmap XML Parser - With Host Deduplication

Uses the host deduplication service to eliminate duplicate host entries
and maintain scan history.
"""

from typing import Dict, Optional, Any
from datetime import datetime
from lxml import etree
from sqlalchemy.orm import Session
from app.db import models
from app.services.host_deduplication_service import HostDeduplicationService
from app.services.subnet_correlation import SubnetCorrelationService
import logging
import time

logger = logging.getLogger(__name__)


class NmapXMLParser:
    def __init__(self, db: Session):
        self.db = db
        self.dedup_service = HostDeduplicationService(db)
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        start_time = time.time()
        logger.info(f"Starting streamed parse of {filename}")

        try:
            scan = self._stream_parse(file_path, filename)
            elapsed_time = time.time() - start_time
            logger.info(f"Successfully parsed {filename} in {elapsed_time:.2f} seconds")
            return scan
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Error parsing XML file {filename} after {elapsed_time:.2f} seconds: {str(e)}")
            raise

    def _stream_parse(self, file_path: str, filename: str) -> models.Scan:
        scan: Optional[models.Scan] = None
        scan_id: Optional[int] = None
        hosts_processed = 0

        context = etree.iterparse(file_path, events=("start", "end"))

        for event, elem in context:
            tag = self._strip_namespace(elem.tag)

            if event == "start" and tag == "nmaprun":
                scan = self._create_scan_record(elem, filename)
                scan_id = scan.id
                continue

            if scan_id is None:
                continue

            if event == "end":
                if tag == "scaninfo":
                    self._parse_scan_info_element(elem, scan_id)
                    self._clear_element(elem)
                elif tag == "host":
                    if self._host_has_address(elem):
                        try:
                            self._process_host_with_deduplication(elem, scan_id)
                            hosts_processed += 1
                            if hosts_processed % 100 == 0:
                                logger.info(f"Processed {hosts_processed} hosts so far")
                        finally:
                            self._clear_element(elem)
                    else:
                        self._clear_element(elem)
                elif tag == "finished" and scan is not None:
                    self._update_scan_end_time(scan, elem)
                    self._clear_element(elem)

        if scan is None or scan_id is None:
            raise ValueError("Unable to locate nmaprun element in XML")

        # Correlate hosts to subnets
        try:
            logger.info(f"Starting subnet correlation for scan {scan_id}")
            hosts_correlated = self.correlation_service.batch_correlate_scan_hosts_to_subnets(scan_id)
            logger.info(f"Correlated {hosts_correlated} hosts to subnets")
        except Exception as e:  # pragma: no cover - defensive
            logger.error(f"Error in subnet correlation: {e}")

        logger.info(f"Parsed {hosts_processed} host records from {filename}")
        return scan

    def _create_scan_record(self, nmaprun_elem: etree.Element, filename: str) -> models.Scan:
        scan = models.Scan(
            filename=filename,
            scan_type='nmap',
            version=nmaprun_elem.get('version'),
            xml_output_version=nmaprun_elem.get('xmloutputversion'),
            command_line=nmaprun_elem.get('args', ''),
            tool_name='nmap',
        )

        self.db.add(scan)
        self.db.flush()
        return scan

    def _parse_scan_info_element(self, scaninfo_elem: etree.Element, scan_id: int):
        scan_info = models.ScanInfo(
            scan_id=scan_id,
            type=scaninfo_elem.get('type'),
            protocol=scaninfo_elem.get('protocol'),
            numservices=int(scaninfo_elem.get('numservices', 0)),
            services=scaninfo_elem.get('services'),
        )
        self.db.add(scan_info)

    def _update_scan_end_time(self, scan: models.Scan, finished_elem: etree.Element) -> None:
        end_time_str = finished_elem.get('timestr')
        if end_time_str:
            try:
                scan.end_time = datetime.strptime(end_time_str, '%a %b %d %H:%M:%S %Y')
            except ValueError:
                logger.warning(f"Could not parse end time: {end_time_str}")

    def _strip_namespace(self, tag: str) -> str:
        return tag.split('}', 1)[-1] if '}' in tag else tag

    def _clear_element(self, elem: etree.Element) -> None:
        parent = elem.getparent()
        elem.clear()
        if parent is not None:
            while elem.getprevious() is not None:
                del parent[0]

    def _host_has_address(self, host_elem: etree.Element) -> bool:
        address_elem = host_elem.find('address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host_elem.find('address[@addrtype="ipv6"]')
        return address_elem is not None

    def _process_host_with_deduplication(self, host_elem: etree.Element, scan_id: int):
        """Process a single host using deduplication"""
        # Extract IP address
        address_elem = host_elem.find('address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host_elem.find('address[@addrtype="ipv6"]')
        
        if address_elem is None:
            logger.warning("Host without IP address, skipping")
            return
        
        ip_address = address_elem.get('addr')
        if not ip_address:
            return
        
        # Extract host data
        host_data = self._extract_host_data(host_elem)
        
        # Find or create deduplicated host
        host = self.dedup_service.find_or_create_host(ip_address, scan_id, host_data)
        
        # Process ports
        self._process_host_ports(host_elem, host.id, scan_id)
        
        # Process host scripts
        self._process_host_scripts(host_elem, host.id, scan_id)

    def _extract_host_data(self, host_elem: etree.Element) -> Dict[str, Any]:
        """Extract host information from XML element"""
        host_data = {}
        
        # Extract hostname
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            hostname_elem = hostnames.find('hostname')
            if hostname_elem is not None:
                host_data['hostname'] = hostname_elem.get('name')
        
        # Extract status
        status = host_elem.find('status')
        if status is not None:
            host_data['state'] = status.get('state')
            host_data['state_reason'] = status.get('reason')
        
        # Extract OS information
        os_elem = host_elem.find('os')
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                host_data['os_name'] = osmatch.get('name')
                host_data['os_accuracy'] = int(osmatch.get('accuracy', 0))
                
                # Extract OS class info
                osclass = osmatch.find('osclass')
                if osclass is not None:
                    host_data['os_family'] = osclass.get('osfamily')
                    host_data['os_generation'] = osclass.get('osgen')
                    host_data['os_type'] = osclass.get('type')
                    host_data['os_vendor'] = osclass.get('vendor')
        
        return host_data

    def _process_host_ports(self, host_elem: etree.Element, host_id: int, scan_id: int):
        """Process ports for a host with deduplication"""
        ports_elem = host_elem.find('ports')
        if ports_elem is None:
            return
        
        for port_elem in ports_elem.findall('port'):
            port_data = self._extract_port_data(port_elem)
            
            # Find or create deduplicated port
            port = self.dedup_service.find_or_create_port(host_id, scan_id, port_data)
            
            # Process port scripts
            self._process_port_scripts(port_elem, port.id, scan_id)

    def _extract_port_data(self, port_elem: etree.Element) -> Dict[str, Any]:
        """Extract port information from XML element"""
        port_data = {
            'port_number': int(port_elem.get('portid')),
            'protocol': port_elem.get('protocol', 'tcp')
        }
        
        # Extract state
        state_elem = port_elem.find('state')
        if state_elem is not None:
            port_data['state'] = state_elem.get('state')
            port_data['reason'] = state_elem.get('reason')
        
        # Extract service info
        service_elem = port_elem.find('service')
        if service_elem is not None:
            port_data.update({
                'service_name': service_elem.get('name'),
                'service_product': service_elem.get('product'),
                'service_version': service_elem.get('version'),
                'service_extrainfo': service_elem.get('extrainfo'),
                'service_method': service_elem.get('method'),
                'service_conf': int(service_elem.get('conf', 0))
            })
        
        return port_data

    def _process_port_scripts(self, port_elem: etree.Element, port_id: int, scan_id: int):
        """Process scripts for a port"""
        for script_elem in port_elem.findall('script'):
            script_data = {
                'script_id': script_elem.get('id'),
                'output': script_elem.get('output', '')
            }
            
            self.dedup_service.add_or_update_script(port_id, scan_id, script_data)

    def _process_host_scripts(self, host_elem: etree.Element, host_id: int, scan_id: int):
        """Process host scripts"""
        for script_elem in host_elem.findall('.//script'):
            # Skip port scripts (they're handled separately)
            if script_elem.getparent().tag == 'port':
                continue
                
            script_data = {
                'script_id': script_elem.get('id'),
                'output': script_elem.get('output', '')
            }
            self.dedup_service.add_or_update_host_script(host_id, scan_id, script_data)
