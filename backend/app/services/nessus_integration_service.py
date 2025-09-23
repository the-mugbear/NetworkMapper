"""
Nessus Integration Service - Simplified Version

Integrates Nessus vulnerability data with NetworkMapper without risk assessment dependencies.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.parsers.nessus_parser import NessusParser, NessusHost, NessusVulnerability
from app.db.models import Host, Port, Scan

logger = logging.getLogger(__name__)


class NessusIntegrationService:
    """Service for integrating Nessus scan data with NetworkMapper"""

    def __init__(self, db: Session):
        self.db = db
        self.parser = NessusParser()

    def process_nessus_file(self, file_path: str, scan_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a Nessus file and integrate the data into NetworkMapper

        Args:
            file_path: Path to the Nessus XML file
            scan_name: Optional custom name for the scan

        Returns:
            Dictionary with processing results
        """
        try:
            # Parse the Nessus file
            nessus_data = self.parser.parse_file(file_path)

            # Create scan record
            scan = self._create_scan_record(nessus_data, scan_name, file_path)

            # Process hosts and vulnerabilities
            hosts_processed = 0
            vulnerabilities_found = 0

            for nessus_host in nessus_data.get('hosts', []):
                host = self._process_nessus_host(nessus_host, scan)
                if host:
                    hosts_processed += 1
                    # Count vulnerabilities for this host
                    vulnerabilities_found += len(nessus_host.vulnerabilities)

            self.db.commit()

            return {
                'success': True,
                'scan_id': scan.id,
                'hosts_processed': hosts_processed,
                'vulnerabilities_found': vulnerabilities_found,
                'scan_name': scan.filename,
                'message': f'Successfully processed Nessus scan with {hosts_processed} hosts and {vulnerabilities_found} vulnerabilities'
            }

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error processing Nessus file {file_path}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to process Nessus file: {str(e)}'
            }

    def _create_scan_record(self, nessus_data: Dict[str, Any], scan_name: Optional[str], file_path: str) -> Scan:
        """Create a scan record from Nessus data"""

        scan_info = nessus_data.get('scan_info', {})

        # Use provided name or derive from metadata
        if scan_name:
            filename = scan_name
        else:
            filename = scan_info.get('scan_name', f"nessus_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        scan = Scan(
            filename=filename,
            scan_type="nessus",
            tool_name="Nessus",
            start_time=scan_info.get('start_time'),
            end_time=scan_info.get('end_time'),
            version=scan_info.get('scanner_version'),
            created_at=datetime.utcnow()
        )

        self.db.add(scan)
        self.db.flush()  # Get the scan ID

        return scan

    def _process_nessus_host(self, nessus_host: NessusHost, scan: Scan) -> Optional[Host]:
        """Process a single Nessus host and create/update host record"""

        try:
            # Check if host already exists
            existing_host = self.db.query(Host).filter(Host.ip_address == nessus_host.ip).first()

            if existing_host:
                # Update existing host
                host = existing_host
                self._update_host_from_nessus(host, nessus_host)
            else:
                # Create new host
                host = self._create_host_from_nessus(nessus_host, scan)

            # Process vulnerabilities as port scripts or host scripts
            self._process_nessus_vulnerabilities(host, nessus_host, scan)

            return host

        except Exception as e:
            logger.error(f"Error processing Nessus host {nessus_host.ip}: {str(e)}")
            return None

    def _create_host_from_nessus(self, nessus_host: NessusHost, scan: Scan) -> Host:
        """Create a new host from Nessus data"""

        host = Host(
            ip_address=nessus_host.ip,
            hostname=nessus_host.hostname or nessus_host.netbios_name,
            state='up',  # Nessus only scans live hosts
            os_name=nessus_host.operating_system,
            last_updated_scan_id=scan.id,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )

        self.db.add(host)
        self.db.flush()

        return host

    def _update_host_from_nessus(self, host: Host, nessus_host: NessusHost):
        """Update existing host with Nessus data"""

        # Update hostname if we have one and current is empty
        if nessus_host.hostname and not host.hostname:
            host.hostname = nessus_host.hostname
        elif nessus_host.netbios_name and not host.hostname:
            host.hostname = nessus_host.netbios_name

        # Update OS if we have better info
        if nessus_host.operating_system and not host.os_name:
            host.os_name = nessus_host.operating_system

        # Update last seen
        host.last_seen = datetime.utcnow()

    def _process_nessus_vulnerabilities(self, host: Host, nessus_host: NessusHost, scan: Scan):
        """Process vulnerabilities as script outputs attached to ports or host"""

        # Group vulnerabilities by port
        port_vulns = {}
        host_vulns = []

        for vuln in nessus_host.vulnerabilities:
            if vuln.port and vuln.port != 0:
                if vuln.port not in port_vulns:
                    port_vulns[vuln.port] = []
                port_vulns[vuln.port].append(vuln)
            else:
                host_vulns.append(vuln)

        # Process port-specific vulnerabilities
        for port_num, vulns in port_vulns.items():
            port = self._get_or_create_port(host, port_num, scan)
            self._attach_vulnerabilities_to_port(port, vulns, scan)

        # Process host-level vulnerabilities
        if host_vulns:
            self._attach_vulnerabilities_to_host(host, host_vulns, scan)

    def _get_or_create_port(self, host: Host, port_num: int, scan: Scan) -> Port:
        """Get existing port or create new one"""

        # Try to find existing port
        existing_port = self.db.query(Port).filter(
            Port.host_id == host.id,
            Port.port_number == port_num,
            Port.protocol == 'tcp'  # Nessus typically uses TCP
        ).first()

        if existing_port:
            existing_port.last_seen = datetime.utcnow()
            existing_port.last_updated_scan_id = scan.id
            return existing_port

        # Create new port
        port = Port(
            host_id=host.id,
            port_number=port_num,
            protocol='tcp',
            state='open',  # Assume open if Nessus found vulns
            last_updated_scan_id=scan.id,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )

        self.db.add(port)
        self.db.flush()

        return port

    def _attach_vulnerabilities_to_port(self, port: Port, vulnerabilities: List[NessusVulnerability], scan: Scan):
        """Attach vulnerabilities as script output to a port"""

        from app.db.models import Script

        # Create a summary script with all vulnerabilities
        vuln_summary = self._format_vulnerabilities_summary(vulnerabilities)

        script = Script(
            port_id=port.id,
            script_id='nessus-vulns',
            output=vuln_summary,
            scan_id=scan.id,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )

        self.db.add(script)

    def _attach_vulnerabilities_to_host(self, host: Host, vulnerabilities: List[NessusVulnerability], scan: Scan):
        """Attach vulnerabilities as script output to a host"""

        from app.db.models import HostScript

        # Create a summary script with all vulnerabilities
        vuln_summary = self._format_vulnerabilities_summary(vulnerabilities)

        script = HostScript(
            host_id=host.id,
            script_id='nessus-vulns',
            output=vuln_summary,
            scan_id=scan.id,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )

        self.db.add(script)

    def _format_vulnerabilities_summary(self, vulnerabilities: List[NessusVulnerability]) -> str:
        """Format vulnerabilities into a readable summary"""

        if not vulnerabilities:
            return "No vulnerabilities found"

        summary_lines = [f"Nessus Vulnerabilities ({len(vulnerabilities)} found):"]
        summary_lines.append("=" * 50)

        # Group by severity
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.severity or 'Unknown'
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)

        # Sort severities (Critical, High, Medium, Low, Info)
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown']

        for severity in severity_order:
            if severity in by_severity:
                vulns = by_severity[severity]
                summary_lines.append(f"\n{severity} ({len(vulns)}):")

                for vuln in vulns[:5]:  # Limit to first 5 per severity
                    cve_info = f" (CVE: {vuln.cve})" if vuln.cve else ""
                    summary_lines.append(f"  • {vuln.plugin_name}{cve_info}")

                if len(vulns) > 5:
                    summary_lines.append(f"  ... and {len(vulns) - 5} more")

        return "\n".join(summary_lines)