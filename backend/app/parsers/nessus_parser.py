"""
Nessus XML Parser

Parses Nessus XML output files to extract vulnerability and host information
for integration with the risk assessment system.
"""

import xml.etree.ElementTree as ET
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass
from decimal import Decimal

logger = logging.getLogger(__name__)


@dataclass
class NessusVulnerability:
    """Represents a vulnerability finding from Nessus"""
    plugin_id: str
    plugin_name: str
    severity: int  # 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    risk_factor: str
    cvss_base_score: Optional[float]
    cvss_vector: Optional[str]
    cvss3_base_score: Optional[float]
    cvss3_vector: Optional[str]
    cve_list: List[str]
    description: str
    solution: str
    synopsis: str
    plugin_output: Optional[str]
    port: int
    protocol: str
    service_name: Optional[str]
    exploitable: bool
    patch_publication_date: Optional[datetime]
    vuln_publication_date: Optional[datetime]


@dataclass
class NessusHost:
    """Represents a host from Nessus scan"""
    ip_address: str
    hostname: Optional[str]
    operating_system: Optional[str]
    mac_address: Optional[str]
    netbios_name: Optional[str]
    fqdn: Optional[str]
    vulnerabilities: List[NessusVulnerability]
    host_properties: Dict[str, str]


class NessusParser:
    """Parser for Nessus XML vulnerability scan files"""

    def __init__(self):
        self.severity_mapping = {
            0: "Info",
            1: "Low",
            2: "Medium",
            3: "High",
            4: "Critical"
        }

    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse Nessus XML file and return structured data"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            if root.tag != 'NessusClientData_v2':
                raise ValueError("Not a valid Nessus XML file")

            return self._parse_nessus_data(root)

        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            raise ValueError(f"Invalid XML format: {e}")
        except Exception as e:
            logger.error(f"Error parsing Nessus file: {e}")
            raise

    def parse_content(self, content: str) -> Dict[str, Any]:
        """Parse Nessus XML content and return structured data"""
        try:
            root = ET.fromstring(content)

            if root.tag != 'NessusClientData_v2':
                raise ValueError("Not a valid Nessus XML file")

            return self._parse_nessus_data(root)

        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            raise ValueError(f"Invalid XML format: {e}")
        except Exception as e:
            logger.error(f"Error parsing Nessus content: {e}")
            raise

    def _parse_nessus_data(self, root: ET.Element) -> Dict[str, Any]:
        """Parse the main Nessus data structure"""
        scan_info = {}
        hosts = []

        # Parse scan metadata
        policy = root.find('.//Policy')
        if policy is not None:
            scan_info['policy_name'] = policy.find('policyName').text if policy.find('policyName') is not None else None

        # Parse report metadata
        report = root.find('.//Report')
        if report is not None:
            scan_info['report_name'] = report.get('name', 'Unknown')

        # Parse hosts
        for report_host in root.findall('.//ReportHost'):
            try:
                host = self._parse_host(report_host)
                if host:
                    hosts.append(host)
            except Exception as e:
                logger.warning(f"Error parsing host: {e}")
                continue

        # Generate scan statistics
        stats = self._generate_scan_stats(hosts)

        return {
            'scan_info': scan_info,
            'hosts': hosts,
            'statistics': stats,
            'parser_type': 'nessus',
            'parser_version': '1.0'
        }

    def _parse_host(self, report_host: ET.Element) -> Optional[NessusHost]:
        """Parse a single host from the report"""
        host_properties = {}
        vulnerabilities = []

        # Parse host properties
        for host_prop in report_host.findall('.//HostProperties/tag'):
            name = host_prop.get('name')
            text = host_prop.text
            if name and text:
                host_properties[name] = text

        # Extract key host information
        ip_address = host_properties.get('host-ip')
        if not ip_address:
            # Fallback to name attribute
            ip_address = report_host.get('name')

        if not ip_address:
            logger.warning("Host without IP address found, skipping")
            return None

        hostname = host_properties.get('host-fqdn') or host_properties.get('netbios-name')
        operating_system = self._extract_os_info(host_properties)
        mac_address = host_properties.get('mac-address')
        netbios_name = host_properties.get('netbios-name')
        fqdn = host_properties.get('host-fqdn')

        # Parse vulnerability items
        for report_item in report_host.findall('.//ReportItem'):
            try:
                vuln = self._parse_vulnerability(report_item)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.warning(f"Error parsing vulnerability: {e}")
                continue

        return NessusHost(
            ip_address=ip_address,
            hostname=hostname,
            operating_system=operating_system,
            mac_address=mac_address,
            netbios_name=netbios_name,
            fqdn=fqdn,
            vulnerabilities=vulnerabilities,
            host_properties=host_properties
        )

    def _parse_vulnerability(self, report_item: ET.Element) -> Optional[NessusVulnerability]:
        """Parse a vulnerability from a ReportItem"""
        plugin_id = report_item.get('pluginID')
        plugin_name = report_item.get('pluginName', 'Unknown')
        port = int(report_item.get('port', 0))
        protocol = report_item.get('protocol', 'tcp')
        service_name = report_item.get('svc_name')
        severity = int(report_item.get('severity', 0))

        # Parse vulnerability details
        risk_factor = self._get_text_or_none(report_item, 'risk_factor')
        description = self._get_text_or_none(report_item, 'description', '')
        solution = self._get_text_or_none(report_item, 'solution', '')
        synopsis = self._get_text_or_none(report_item, 'synopsis', '')
        plugin_output = self._get_text_or_none(report_item, 'plugin_output')

        # Parse CVSS scores
        cvss_base_score = self._parse_float(self._get_text_or_none(report_item, 'cvss_base_score'))
        cvss_vector = self._get_text_or_none(report_item, 'cvss_vector')
        cvss3_base_score = self._parse_float(self._get_text_or_none(report_item, 'cvss3_base_score'))
        cvss3_vector = self._get_text_or_none(report_item, 'cvss3_vector')

        # Parse CVE list
        cve_list = []
        cve_text = self._get_text_or_none(report_item, 'cve')
        if cve_text:
            # CVEs are often comma-separated
            cve_list = [cve.strip() for cve in cve_text.split(',') if cve.strip()]

        # Parse dates
        patch_publication_date = self._parse_date(self._get_text_or_none(report_item, 'patch_publication_date'))
        vuln_publication_date = self._parse_date(self._get_text_or_none(report_item, 'vuln_publication_date'))

        # Determine if exploitable
        exploitable = self._is_exploitable(report_item)

        # Map severity to risk factor if not provided
        if not risk_factor:
            risk_factor = self.severity_mapping.get(severity, "Info")

        return NessusVulnerability(
            plugin_id=plugin_id,
            plugin_name=plugin_name,
            severity=severity,
            risk_factor=risk_factor,
            cvss_base_score=cvss_base_score,
            cvss_vector=cvss_vector,
            cvss3_base_score=cvss3_base_score,
            cvss3_vector=cvss3_vector,
            cve_list=cve_list,
            description=description,
            solution=solution,
            synopsis=synopsis,
            plugin_output=plugin_output,
            port=port,
            protocol=protocol,
            service_name=service_name,
            exploitable=exploitable,
            patch_publication_date=patch_publication_date,
            vuln_publication_date=vuln_publication_date
        )

    def _extract_os_info(self, host_properties: Dict[str, str]) -> Optional[str]:
        """Extract operating system information from host properties"""
        # Try different OS detection methods used by Nessus
        os_candidates = [
            host_properties.get('operating-system'),
            host_properties.get('os'),
            host_properties.get('HOST_START_os'),
            host_properties.get('system-type')
        ]

        for os_info in os_candidates:
            if os_info and os_info.strip():
                return os_info.strip()

        return None

    def _get_text_or_none(self, element: ET.Element, tag: str, default: Optional[str] = None) -> Optional[str]:
        """Get text content of a child element or return None/default"""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    def _parse_float(self, value: Optional[str]) -> Optional[float]:
        """Parse string to float, return None if invalid"""
        if not value:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime object"""
        if not date_str:
            return None

        # Common date formats used by Nessus
        date_formats = [
            '%Y/%m/%d',
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%d/%m/%Y',
            '%Y/%m/%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S'
        ]

        for fmt in date_formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        logger.warning(f"Could not parse date: {date_str}")
        return None

    def _is_exploitable(self, report_item: ET.Element) -> bool:
        """Determine if vulnerability is exploitable based on various indicators"""
        # Check for explicit exploit information
        exploit_available = self._get_text_or_none(report_item, 'exploit_available')
        if exploit_available and exploit_available.lower() == 'true':
            return True

        # Check for metasploit modules
        metasploit = self._get_text_or_none(report_item, 'metasploit_name')
        if metasploit:
            return True

        # Check for core impact modules
        core_impact = self._get_text_or_none(report_item, 'core_impact_name')
        if core_impact:
            return True

        # Check exploit frameworks
        canvas = self._get_text_or_none(report_item, 'canvas_package')
        if canvas:
            return True

        # Check for known exploit code
        exploit_code = self._get_text_or_none(report_item, 'exploit_code_maturity')
        if exploit_code and exploit_code.lower() in ['functional', 'high', 'proof-of-concept']:
            return True

        return False

    def _generate_scan_stats(self, hosts: List[NessusHost]) -> Dict[str, Any]:
        """Generate statistics from the parsed scan data"""
        total_hosts = len(hosts)
        total_vulns = sum(len(host.vulnerabilities) for host in hosts)

        # Count vulnerabilities by severity
        severity_counts = {severity: 0 for severity in self.severity_mapping.values()}

        for host in hosts:
            for vuln in host.vulnerabilities:
                severity_name = self.severity_mapping.get(vuln.severity, "Info")
                severity_counts[severity_name] += 1

        # Count hosts with vulnerabilities by severity
        hosts_by_severity = {severity: 0 for severity in self.severity_mapping.values()}

        for host in hosts:
            host_severities = set()
            for vuln in host.vulnerabilities:
                severity_name = self.severity_mapping.get(vuln.severity, "Info")
                host_severities.add(severity_name)

            for severity in host_severities:
                hosts_by_severity[severity] += 1

        # Count exploitable vulnerabilities
        exploitable_vulns = sum(
            1 for host in hosts
            for vuln in host.vulnerabilities
            if vuln.exploitable
        )

        # Count unique CVEs
        unique_cves = set()
        for host in hosts:
            for vuln in host.vulnerabilities:
                unique_cves.update(vuln.cve_list)

        # Operating system distribution
        os_distribution = {}
        for host in hosts:
            if host.operating_system:
                # Normalize OS name
                os_key = self._normalize_os_name(host.operating_system)
                os_distribution[os_key] = os_distribution.get(os_key, 0) + 1

        return {
            'total_hosts': total_hosts,
            'total_vulnerabilities': total_vulns,
            'vulnerability_counts': severity_counts,
            'hosts_by_severity': hosts_by_severity,
            'exploitable_vulnerabilities': exploitable_vulns,
            'unique_cves': len(unique_cves),
            'cve_list': sorted(list(unique_cves)),
            'os_distribution': os_distribution,
            'scan_date': datetime.utcnow().isoformat()
        }

    def _normalize_os_name(self, os_name: str) -> str:
        """Normalize operating system name for consistent grouping"""
        os_lower = os_name.lower()

        if 'windows' in os_lower:
            if 'server' in os_lower:
                if '2019' in os_lower:
                    return 'Windows Server 2019'
                elif '2016' in os_lower:
                    return 'Windows Server 2016'
                elif '2012' in os_lower:
                    return 'Windows Server 2012'
                elif '2008' in os_lower:
                    return 'Windows Server 2008'
                else:
                    return 'Windows Server (Other)'
            else:
                if '10' in os_lower:
                    return 'Windows 10'
                elif '11' in os_lower:
                    return 'Windows 11'
                elif '7' in os_lower:
                    return 'Windows 7'
                else:
                    return 'Windows (Other)'
        elif 'linux' in os_lower:
            if 'ubuntu' in os_lower:
                return 'Ubuntu Linux'
            elif 'centos' in os_lower:
                return 'CentOS Linux'
            elif 'redhat' in os_lower or 'rhel' in os_lower:
                return 'Red Hat Linux'
            elif 'debian' in os_lower:
                return 'Debian Linux'
            else:
                return 'Linux (Other)'
        elif 'vmware' in os_lower:
            return 'VMware ESXi'
        elif 'cisco' in os_lower:
            return 'Cisco IOS'
        else:
            return os_name[:50]  # Truncate long OS names

    def get_supported_extensions(self) -> List[str]:
        """Return list of supported file extensions"""
        return ['.nessus', '.xml']

    def validate_file(self, file_path: str) -> Tuple[bool, str]:
        """Validate if file is a supported Nessus XML file"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            if root.tag != 'NessusClientData_v2':
                return False, "Not a valid Nessus XML file (missing NessusClientData_v2 root)"

            # Check for required elements
            if not root.find('.//Report'):
                return False, "No Report section found in Nessus file"

            return True, "Valid Nessus XML file"

        except ET.ParseError as e:
            return False, f"XML parsing error: {e}"
        except Exception as e:
            return False, f"File validation error: {e}"