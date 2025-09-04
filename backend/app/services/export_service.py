import json
import csv
import io
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db import models
from app.services.dns_service import DNSService
import logging

logger = logging.getLogger(__name__)

class ExportService:
    def __init__(self, db: Session):
        self.db = db
        self.dns_service = DNSService(db)

    def export_scope_report(self, scope_id: int, format_type: str = 'json') -> Dict[str, Any]:
        """Export comprehensive report for a scope"""
        scope = self.db.query(models.Scope).filter(models.Scope.id == scope_id).first()
        if not scope:
            raise ValueError(f"Scope with ID {scope_id} not found")
        
        # Gather all data for the scope
        report_data = self._gather_scope_data(scope)
        
        if format_type.lower() == 'json':
            return self._format_json_report(report_data)
        elif format_type.lower() == 'csv':
            return self._format_csv_report(report_data)
        elif format_type.lower() == 'html':
            return self._format_html_report(report_data)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def export_scan_report(self, scan_id: int, format_type: str = 'json') -> Dict[str, Any]:
        """Export report for a specific scan"""
        scan = self.db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found")
        
        report_data = self._gather_scan_data(scan)
        
        if format_type.lower() == 'json':
            return self._format_json_report(report_data)
        elif format_type.lower() == 'csv':
            return self._format_csv_report(report_data)
        elif format_type.lower() == 'html':
            return self._format_html_report(report_data)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def export_out_of_scope_report(self, format_type: str = 'json') -> Dict[str, Any]:
        """Export report of all out-of-scope findings"""
        out_of_scope_hosts = self.db.query(models.OutOfScopeHost).all()
        
        report_data = {
            'report_type': 'out_of_scope_findings',
            'generated_at': datetime.utcnow().isoformat(),
            'total_out_of_scope_hosts': len(out_of_scope_hosts),
            'findings': []
        }
        
        # Group by tool source
        by_tool = {}
        for host in out_of_scope_hosts:
            tool = host.tool_source or 'unknown'
            if tool not in by_tool:
                by_tool[tool] = []
            
            finding = {
                'ip_address': host.ip_address,
                'hostname': host.hostname,
                'ports': host.ports or {},
                'reason': host.reason,
                'found_at': host.created_at.isoformat() if host.created_at else None,
                'scan_id': host.scan_id
            }
            
            # Try to get scan information
            scan = self.db.query(models.Scan).filter(models.Scan.id == host.scan_id).first()
            if scan:
                finding['scan_filename'] = scan.filename
                finding['scan_type'] = scan.scan_type
                finding['tool_name'] = scan.tool_name
            
            by_tool[tool].append(finding)
        
        report_data['findings_by_tool'] = by_tool
        report_data['findings'] = [finding for findings in by_tool.values() for finding in findings]
        
        if format_type.lower() == 'json':
            return self._format_json_report(report_data)
        elif format_type.lower() == 'csv':
            return self._format_csv_report(report_data)
        elif format_type.lower() == 'html':
            return self._format_html_report(report_data)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def _gather_scope_data(self, scope: models.Scope) -> Dict[str, Any]:
        """Gather all data related to a scope"""
        # Get all subnet mappings for this scope
        mappings = self.db.query(models.HostSubnetMapping).join(models.Subnet).filter(
            models.Subnet.scope_id == scope.id
        ).all()
        
        # Get unique hosts
        host_ids = list(set([mapping.host_id for mapping in mappings]))
        hosts = self.db.query(models.Host).filter(models.Host.id.in_(host_ids)).all() if host_ids else []
        
        # Get scan information
        scan_ids = list(set([host.scan_id for host in hosts]))
        scans = self.db.query(models.Scan).filter(models.Scan.id.in_(scan_ids)).all() if scan_ids else []
        
        # Get Eyewitness results for these scans
        eyewitness_results = self.db.query(models.EyewitnessResult).filter(
            models.EyewitnessResult.scan_id.in_(scan_ids)
        ).all() if scan_ids else []
        
        # Get out-of-scope hosts from these scans
        out_of_scope = self.db.query(models.OutOfScopeHost).filter(
            models.OutOfScopeHost.scan_id.in_(scan_ids)
        ).all() if scan_ids else []
        
        report_data = {
            'report_type': 'scope_report',
            'generated_at': datetime.utcnow().isoformat(),
            'scope': {
                'id': scope.id,
                'name': scope.name,
                'description': scope.description,
                'created_at': scope.created_at.isoformat() if scope.created_at else None,
                'subnets': [
                    {
                        'id': subnet.id,
                        'cidr': subnet.cidr,
                        'description': subnet.description,
                        'created_at': subnet.created_at.isoformat() if subnet.created_at else None
                    }
                    for subnet in scope.subnets
                ]
            },
            'statistics': {
                'total_subnets': len(scope.subnets),
                'total_hosts': len(hosts),
                'total_scans': len(scans),
                'total_eyewitness_results': len(eyewitness_results),
                'out_of_scope_hosts': len(out_of_scope)
            },
            'scans': [],
            'hosts': [],
            'eyewitness_results': [],
            'out_of_scope_hosts': []
        }
        
        # Add scan details
        for scan in scans:
            scan_data = {
                'id': scan.id,
                'filename': scan.filename,
                'scan_type': scan.scan_type,
                'tool_name': scan.tool_name,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'command_line': scan.command_line,
                'version': scan.version
            }
            report_data['scans'].append(scan_data)
        
        # Add host details with DNS information
        for host in hosts:
            # Get DNS records
            dns_records = self.dns_service.get_stored_dns_records(host.hostname) if host.hostname else []
            
            # Get ports
            ports = [
                {
                    'port_number': port.port_number,
                    'protocol': port.protocol,
                    'state': port.state,
                    'service_name': port.service_name,
                    'service_product': port.service_product,
                    'service_version': port.service_version
                }
                for port in host.ports
            ]
            
            # Get subnet mappings for this host
            host_subnets = [mapping.subnet.cidr for mapping in mappings if mapping.host_id == host.id]
            
            host_data = {
                'id': host.id,
                'ip_address': host.ip_address,
                'hostname': host.hostname,
                'state': host.state,
                'os_name': host.os_name,
                'os_family': host.os_family,
                'scan_id': host.scan_id,
                'ports': ports,
                'subnets': host_subnets,
                'dns_records': [
                    {
                        'domain': record.domain,
                        'record_type': record.record_type,
                        'value': record.value,
                        'ttl': record.ttl
                    }
                    for record in dns_records
                ]
            }
            report_data['hosts'].append(host_data)
        
        # Add Eyewitness results
        for result in eyewitness_results:
            result_data = {
                'id': result.id,
                'url': result.url,
                'ip_address': result.ip_address,
                'port': result.port,
                'title': result.title,
                'server_header': result.server_header,
                'response_code': result.response_code,
                'screenshot_path': result.screenshot_path,
                'scan_id': result.scan_id
            }
            report_data['eyewitness_results'].append(result_data)
        
        # Add out-of-scope hosts
        for oos_host in out_of_scope:
            oos_data = {
                'ip_address': oos_host.ip_address,
                'hostname': oos_host.hostname,
                'ports': oos_host.ports,
                'tool_source': oos_host.tool_source,
                'reason': oos_host.reason,
                'scan_id': oos_host.scan_id,
                'created_at': oos_host.created_at.isoformat() if oos_host.created_at else None
            }
            report_data['out_of_scope_hosts'].append(oos_data)
        
        return report_data

    def _gather_scan_data(self, scan: models.Scan) -> Dict[str, Any]:
        """Gather all data for a specific scan"""
        report_data = {
            'report_type': 'scan_report',
            'generated_at': datetime.utcnow().isoformat(),
            'scan': {
                'id': scan.id,
                'filename': scan.filename,
                'scan_type': scan.scan_type,
                'tool_name': scan.tool_name,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'command_line': scan.command_line,
                'version': scan.version
            },
            'hosts': [],
            'eyewitness_results': [],
            'out_of_scope_hosts': []
        }
        
        # Add host data (similar to scope report but for single scan)
        for host in scan.hosts:
            dns_records = self.dns_service.get_stored_dns_records(host.hostname) if host.hostname else []
            
            ports = [
                {
                    'port_number': port.port_number,
                    'protocol': port.protocol,
                    'state': port.state,
                    'service_name': port.service_name,
                    'service_product': port.service_product,
                    'service_version': port.service_version
                }
                for port in host.ports
            ]
            
            host_data = {
                'id': host.id,
                'ip_address': host.ip_address,
                'hostname': host.hostname,
                'state': host.state,
                'os_name': host.os_name,
                'ports': ports,
                'dns_records': [
                    {
                        'domain': record.domain,
                        'record_type': record.record_type,
                        'value': record.value
                    }
                    for record in dns_records
                ]
            }
            report_data['hosts'].append(host_data)
        
        # Add Eyewitness results
        for result in scan.eyewitness_results:
            result_data = {
                'url': result.url,
                'ip_address': result.ip_address,
                'port': result.port,
                'title': result.title,
                'response_code': result.response_code
            }
            report_data['eyewitness_results'].append(result_data)
        
        # Add out-of-scope hosts
        out_of_scope_hosts = self.db.query(models.OutOfScopeHost).filter(
            models.OutOfScopeHost.scan_id == scan.id
        ).all()
        
        for oos_host in out_of_scope_hosts:
            oos_data = {
                'ip_address': oos_host.ip_address,
                'hostname': oos_host.hostname,
                'ports': oos_host.ports,
                'tool_source': oos_host.tool_source,
                'reason': oos_host.reason
            }
            report_data['out_of_scope_hosts'].append(oos_data)
        
        return report_data

    def _format_json_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format data as JSON"""
        return {
            'content_type': 'application/json',
            'data': data,
            'filename': f"{data['report_type']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        }

    def _format_csv_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format data as CSV"""
        output = io.StringIO()
        
        if data['report_type'] == 'scope_report' or data['report_type'] == 'scan_report':
            # Create CSV for hosts
            writer = csv.writer(output)
            writer.writerow([
                'IP Address', 'Hostname', 'State', 'OS', 'Open Ports', 
                'Subnets', 'DNS Records', 'Scan ID'
            ])
            
            for host in data.get('hosts', []):
                ports_str = '; '.join([f"{p['port_number']}/{p['protocol']}" for p in host['ports']])
                subnets_str = '; '.join(host.get('subnets', []))
                dns_str = '; '.join([f"{r['record_type']}: {r['value']}" for r in host['dns_records']])
                
                writer.writerow([
                    host['ip_address'],
                    host['hostname'] or '',
                    host['state'] or '',
                    host['os_name'] or '',
                    ports_str,
                    subnets_str,
                    dns_str,
                    host['scan_id']
                ])
        
        elif data['report_type'] == 'out_of_scope_findings':
            writer = csv.writer(output)
            writer.writerow([
                'IP Address', 'Hostname', 'Tool Source', 'Reason', 'Ports', 'Found At'
            ])
            
            for finding in data.get('findings', []):
                ports_str = json.dumps(finding['ports']) if finding['ports'] else ''
                writer.writerow([
                    finding['ip_address'],
                    finding['hostname'] or '',
                    finding.get('tool_name', ''),
                    finding['reason'] or '',
                    ports_str,
                    finding['found_at'] or ''
                ])
        
        return {
            'content_type': 'text/csv',
            'data': output.getvalue(),
            'filename': f"{data['report_type']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        }

    def _format_html_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format data as HTML"""
        html_content = self._generate_html_report(data)
        
        return {
            'content_type': 'text/html',
            'data': html_content,
            'filename': f"{data['report_type']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        }

    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetworkMapper Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .out-of-scope {{ background-color: #ffe6e6; }}
                .stats {{ display: flex; gap: 20px; }}
                .stat-box {{ background: #e6f3ff; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>NetworkMapper Report</h1>
                <p><strong>Report Type:</strong> {data['report_type']}</p>
                <p><strong>Generated:</strong> {data['generated_at']}</p>
            </div>
        """
        
        if data['report_type'] == 'scope_report':
            scope = data['scope']
            stats = data['statistics']
            
            html += f"""
            <div class="section">
                <h2>Scope: {scope['name']}</h2>
                <p>{scope['description'] or 'No description provided'}</p>
                
                <div class="stats">
                    <div class="stat-box">
                        <strong>{stats['total_subnets']}</strong><br>Subnets
                    </div>
                    <div class="stat-box">
                        <strong>{stats['total_hosts']}</strong><br>Hosts
                    </div>
                    <div class="stat-box">
                        <strong>{stats['total_scans']}</strong><br>Scans
                    </div>
                    <div class="stat-box">
                        <strong>{stats['out_of_scope_hosts']}</strong><br>Out of Scope
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h3>Subnets</h3>
                <table>
                    <tr><th>CIDR</th><th>Description</th></tr>
            """
            
            for subnet in scope['subnets']:
                html += f"<tr><td>{subnet['cidr']}</td><td>{subnet['description'] or ''}</td></tr>"
            
            html += "</table></div>"
        
        # Add hosts table
        if 'hosts' in data and data['hosts']:
            html += """
            <div class="section">
                <h3>Hosts</h3>
                <table>
                    <tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Open Ports</th><th>DNS Records</th></tr>
            """
            
            for host in data['hosts']:
                ports_str = ', '.join([f"{p['port_number']}/{p['protocol']}" for p in host['ports']])
                dns_str = ', '.join([f"{r['record_type']}" for r in host['dns_records']])
                
                html += f"""
                <tr>
                    <td>{host['ip_address']}</td>
                    <td>{host['hostname'] or ''}</td>
                    <td>{host['os_name'] or ''}</td>
                    <td>{ports_str}</td>
                    <td>{dns_str}</td>
                </tr>
                """
            
            html += "</table></div>"
        
        # Add out-of-scope hosts
        if 'out_of_scope_hosts' in data and data['out_of_scope_hosts']:
            html += """
            <div class="section">
                <h3>Out of Scope Hosts</h3>
                <table>
                    <tr><th>IP Address</th><th>Tool</th><th>Reason</th></tr>
            """
            
            for oos in data['out_of_scope_hosts']:
                html += f"""
                <tr class="out-of-scope">
                    <td>{oos['ip_address']}</td>
                    <td>{oos['tool_source'] or ''}</td>
                    <td>{oos['reason'] or ''}</td>
                </tr>
                """
            
            html += "</table></div>"
        
        html += """
        </body>
        </html>
        """
        
        return html