"""
Nessus Integration Service - Simplified Version

Integrates Nessus vulnerability data with NetworkMapper without risk assessment dependencies.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session

from app.parsers.nessus_parser import NessusParser, NessusHost, NessusVulnerability
# Import from main models (hosts_v2 schema)
from app.db.models import Host, Port, Scan, Script, HostScript
from app.services.vulnerability_service import VulnerabilityService
# Import risk models to ensure SQLAlchemy knows about relationships
from app.db import models_risk
from app.core.config import settings

logger = logging.getLogger(__name__)


class NessusIntegrationService:
    """Service for integrating Nessus scan data with NetworkMapper"""

    def __init__(self, db: Session):
        self.db = db
        self.parser = NessusParser()
        self.vulnerability_service = VulnerabilityService(db)
        self._commit_batch_size = max(1, settings.NESSUS_COMMIT_BATCH_SIZE)

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
            scan_info, hosts_iter = self.parser.iter_file(file_path)

            # Create scan record
            scan = self._create_scan_record(scan_info, scan_name)
            scan_id = scan.id
            scan_label = scan.filename

            # Process hosts and vulnerabilities
            hosts_processed = 0
            vulnerabilities_found = 0

            for nessus_host in hosts_iter:
                result = self._process_nessus_host(nessus_host, scan)
                if result:
                    host, vuln_stats = result
                    hosts_processed += 1
                    vulnerabilities_found += vuln_stats.get("total", 0)

                    if hosts_processed % self._commit_batch_size == 0:
                        self.db.commit()
                        self.db.expunge_all()
                        scan = self.db.get(Scan, scan_id)
                        if not scan:
                            raise RuntimeError("Scan record disappeared during Nessus ingestion")
                # Free memory regardless of success
                if nessus_host.vulnerabilities:
                    nessus_host.vulnerabilities.clear()

            self.db.commit()
            self.db.expunge_all()

            return {
                'success': True,
                'scan_id': scan_id,
                'hosts_processed': hosts_processed,
                'vulnerabilities_found': vulnerabilities_found,
                'scan_name': scan_label,
                'message': (
                    f'Successfully processed Nessus scan with '
                    f'{hosts_processed} hosts and {vulnerabilities_found} vulnerabilities'
                )
            }

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error processing Nessus file {file_path}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': f'Failed to process Nessus file: {str(e)}'
            }

    def _create_scan_record(self, scan_info: Dict[str, Any], scan_name: Optional[str]) -> Scan:
        """Create a scan record from Nessus data"""

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

    def _process_nessus_host(
        self,
        nessus_host: NessusHost,
        scan: Scan,
    ) -> Optional[Tuple[Host, Dict[str, int]]]:
        """Process a single Nessus host and create/update host record"""

        try:
            # Check if host already exists
            existing_host = self.db.query(Host).filter(Host.ip_address == nessus_host.ip_address).first()

            if existing_host:
                # Update existing host
                host = existing_host
                self._update_host_from_nessus(host, nessus_host, scan)
            else:
                # Create new host
                host = self._create_host_from_nessus(nessus_host, scan)

            # CRITICAL FIX: Ensure host gets updated with latest scan ID
            host.last_updated_scan_id = scan.id
            host.last_seen = datetime.utcnow()

            # Process vulnerabilities using new vulnerability service
            vuln_stats = self.vulnerability_service.process_nessus_vulnerabilities(host, nessus_host, scan)
            logger.info(f"Processed {vuln_stats['total']} vulnerabilities for host {host.ip_address}")

            return host, vuln_stats

        except Exception as e:
            logger.error(f"Error processing Nessus host {nessus_host.ip_address}: {str(e)}")
            return None

    def _create_host_from_nessus(self, nessus_host: NessusHost, scan: Scan) -> Host:
        """Create a new host from Nessus data"""

        host = Host(
            ip_address=nessus_host.ip_address,
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

    def _update_host_from_nessus(self, host: Host, nessus_host: NessusHost, scan: Scan):
        """Update existing host with Nessus data"""

        # Update hostname if we have one and current is empty
        if nessus_host.hostname and not host.hostname:
            host.hostname = nessus_host.hostname
        elif nessus_host.netbios_name and not host.hostname:
            host.hostname = nessus_host.netbios_name

        # Update OS if we have better info
        if nessus_host.operating_system and not host.os_name:
            host.os_name = nessus_host.operating_system

        # Update scan tracking
        host.last_updated_scan_id = scan.id
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

        # Create a summary script with all vulnerabilities
        vuln_summary = self._format_vulnerabilities_summary(vulnerabilities)

        # Check if script already exists for this port
        existing_script = self.db.query(Script).filter(
            Script.port_id == port.id,
            Script.script_id == 'nessus-vulns'
        ).first()

        if existing_script:
            # Update existing script
            existing_script.output = vuln_summary
            existing_script.scan_id = scan.id
            existing_script.last_seen = datetime.utcnow()
        else:
            # Create new script
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

        # Create a summary script with all vulnerabilities
        vuln_summary = self._format_vulnerabilities_summary(vulnerabilities)

        # Check if script already exists for this host
        existing_script = self.db.query(HostScript).filter(
            HostScript.host_id == host.id,
            HostScript.script_id == 'nessus-vulns'
        ).first()

        if existing_script:
            # Update existing script
            existing_script.output = vuln_summary
            existing_script.scan_id = scan.id
            existing_script.last_seen = datetime.utcnow()
        else:
            # Create new script
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
        severity_map = {
            0: 'Info',
            1: 'Low',
            2: 'Medium',
            3: 'High',
            4: 'Critical'
        }

        by_severity = {}
        for vuln in vulnerabilities:
            severity = severity_map.get(vuln.severity, 'Unknown')
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
                    cve_info = f" (CVE: {', '.join(vuln.cve_list)})" if vuln.cve_list else ""
                    summary_lines.append(f"  • {vuln.plugin_name}{cve_info}")

                if len(vulns) > 5:
                    summary_lines.append(f"  ... and {len(vulns) - 5} more")

        return "\n".join(summary_lines)
