from typing import Dict, List, Optional, Any
from datetime import datetime
from lxml import etree
from sqlalchemy.orm import Session
from app.db import models
from app.services.subnet_correlation import SubnetCorrelationService
import logging

logger = logging.getLogger(__name__)

class NmapXMLParser:
    def __init__(self, db: Session):
        self.db = db
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        try:
            with open(file_path, 'rb') as f:
                tree = etree.parse(f)
                root = tree.getroot()
                
            return self._parse_root(root, filename)
        except Exception as e:
            logger.error(f"Error parsing XML file {filename}: {str(e)}")
            raise

    def _parse_root(self, root: etree.Element, filename: str) -> models.Scan:
        # Create scan record
        scan = models.Scan(
            filename=filename,
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
        
        # Save scan to get ID
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        
        # Parse scan info details
        self._parse_scan_info(root, scan.id)
        
        # Parse hosts
        for host_elem in root.findall('host'):
            self._parse_host(host_elem, scan.id)
        
        # Correlate all hosts from this scan to subnets
        try:
            mappings_created = self.correlation_service.correlate_scan_hosts_to_subnets(scan.id)
            logger.info(f"Created {mappings_created} host-subnet mappings for scan {scan.id}")
        except Exception as e:
            logger.warning(f"Failed to correlate hosts to subnets for scan {scan.id}: {str(e)}")
            
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
        
        # Get hostname
        hostname = None
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name')
        
        # Get host state
        status_elem = host_elem.find('status')
        state = status_elem.get('state') if status_elem is not None else 'unknown'
        state_reason = status_elem.get('reason') if status_elem is not None else ''
        
        # Parse OS detection
        os_info = self._parse_os(host_elem)
        
        # Create host record
        host = models.Host(
            scan_id=scan_id,
            ip_address=ip_address,
            hostname=hostname,
            state=state,
            state_reason=state_reason,
            **os_info
        )
        
        self.db.add(host)
        self.db.commit()
        self.db.refresh(host)
        
        # Parse ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                self._parse_port(port_elem, host.id)
        
        # Parse host scripts
        hostscript_elem = host_elem.find('hostscript')
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
        self.db.commit()
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