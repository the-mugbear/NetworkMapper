from typing import Dict, Any, List
from datetime import datetime
from app.services.subnet_calculator import SubnetCalculator
import base64
import json

class ReportTemplates:
    """Professional report templates for NetworkMapper exports"""
    
    @staticmethod
    def get_css_styles() -> str:
        """Professional CSS styling for HTML reports"""
        return """
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background-color: #f8f9fa;
                color: #333;
            }
            
            .report-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            
            .report-title {
                font-size: 2.5em;
                font-weight: 700;
                margin-bottom: 10px;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            }
            
            .report-subtitle {
                font-size: 1.2em;
                opacity: 0.9;
                margin-bottom: 0;
            }
            
            .executive-summary {
                background: white;
                border-left: 5px solid #28a745;
                padding: 25px;
                margin-bottom: 30px;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            
            .section {
                background: white;
                margin-bottom: 30px;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            }
            
            .section-header {
                background-color: #f8f9fa;
                padding: 20px;
                border-bottom: 2px solid #dee2e6;
                font-size: 1.4em;
                font-weight: 600;
                color: #495057;
            }
            
            .section-content {
                padding: 25px;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 20px;
                text-align: center;
                transition: transform 0.2s ease;
            }
            
            .stat-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
            
            .stat-value {
                font-size: 2.2em;
                font-weight: 700;
                color: #007bff;
                margin-bottom: 5px;
            }
            
            .stat-label {
                color: #6c757d;
                font-size: 0.9em;
                text-transform: uppercase;
                font-weight: 600;
                letter-spacing: 1px;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            
            th {
                background: linear-gradient(135deg, #495057 0%, #6c757d 100%);
                color: white;
                font-weight: 600;
                padding: 15px 12px;
                text-align: left;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            td {
                padding: 12px;
                border-bottom: 1px solid #dee2e6;
                vertical-align: top;
            }
            
            tr:nth-child(even) {
                background-color: #f8f9fa;
            }
            
            tr:hover {
                background-color: #e3f2fd;
                transition: background-color 0.2s ease;
            }
            
            .risk-critical { background-color: #f8d7da; color: #721c24; }
            .risk-high { background-color: #fff3cd; color: #856404; }
            .risk-medium { background-color: #cce5ff; color: #004085; }
            .risk-low { background-color: #d4edda; color: #155724; }
            .risk-unknown { background-color: #f8f9fa; color: #6c757d; }
            
            .badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .badge-success { background-color: #28a745; color: white; }
            .badge-warning { background-color: #ffc107; color: #212529; }
            .badge-danger { background-color: #dc3545; color: white; }
            .badge-info { background-color: #17a2b8; color: white; }
            .badge-secondary { background-color: #6c757d; color: white; }
            
            .recommendations {
                background: #fff3cd;
                border: 1px solid #ffeeba;
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
            }
            
            .recommendations h4 {
                color: #856404;
                margin-bottom: 15px;
            }
            
            .recommendation-item {
                background: white;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 10px 0;
                border-radius: 0 5px 5px 0;
            }
            
            .out-of-scope {
                background-color: #f8d7da;
                border-left: 4px solid #dc3545;
            }
            
            .footer {
                text-align: center;
                padding: 30px;
                color: #6c757d;
                font-size: 0.9em;
                border-top: 2px solid #dee2e6;
                margin-top: 50px;
            }
            
            .logo {
                float: right;
                max-height: 60px;
                margin-left: 20px;
            }
            
            .metadata {
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
                gap: 10px;
                font-size: 0.9em;
                opacity: 0.9;
            }
            
            .chart-placeholder {
                background: #f8f9fa;
                border: 2px dashed #dee2e6;
                border-radius: 8px;
                padding: 40px;
                text-align: center;
                color: #6c757d;
                margin: 20px 0;
            }
            
            @media print {
                body { background-color: white; }
                .section { page-break-inside: avoid; }
                .report-header { background: #667eea !important; }
                .stat-card:hover { transform: none; }
                tr:hover { background-color: transparent; }
            }
            
            @media (max-width: 768px) {
                .stats-grid { grid-template-columns: 1fr; }
                .metadata { flex-direction: column; align-items: flex-start; }
                .logo { float: none; margin: 10px 0; }
            }
        </style>
        """
    
    @staticmethod
    def generate_executive_summary(report_data: Dict[str, Any]) -> str:
        """Generate executive summary based on report data"""
        report_type = report_data.get('report_type', '')
        
        if report_type == 'scope_report':
            return ReportTemplates._generate_scope_executive_summary(report_data)
        elif report_type == 'scan_report':
            return ReportTemplates._generate_scan_executive_summary(report_data)
        elif report_type == 'out_of_scope_findings':
            return ReportTemplates._generate_out_of_scope_summary(report_data)
        else:
            return "This report provides a comprehensive analysis of network discovery results."
    
    @staticmethod
    def _generate_scope_executive_summary(data: Dict[str, Any]) -> str:
        """Generate executive summary for scope reports"""
        stats = data.get('statistics', {})
        scope = data.get('scope', {})
        
        # Calculate subnet metrics if available
        subnet_metrics = []
        for subnet_data in scope.get('subnets', []):
            cidr = subnet_data.get('cidr', '')
            if cidr:
                metrics = SubnetCalculator.calculate_subnet_metrics(cidr)
                metrics['cidr'] = cidr
                subnet_metrics.append(metrics)
        
        aggregates = SubnetCalculator.calculate_scope_aggregates([
            {
                'total_addresses': m['total_addresses'], 
                'usable_addresses': m['usable_addresses'],
                'discovered_hosts': 0,  # We'll update this with actual data
                'utilization_percentage': 0,
                'risk_level': 'unknown'
            } 
            for m in subnet_metrics
        ])
        
        summary = f"""
        <div class="executive-summary">
            <h3>Executive Summary</h3>
            <p><strong>Scope:</strong> {scope.get('name', 'Unknown')} contains {stats.get('total_subnets', 0)} 
            subnet(s) with a total address space of {aggregates.get('total_usable_addresses', 0):,} usable IP addresses.</p>
            
            <p><strong>Discovery Results:</strong> Network scanning discovered {stats.get('total_hosts', 0)} 
            active hosts across {stats.get('total_scans', 0)} scan(s), indicating network utilization and 
            potential security exposure points.</p>
            
            <p><strong>Web Services:</strong> {stats.get('total_eyewitness_results', 0)} web services were 
            identified and catalogued, providing insight into web-based attack surfaces.</p>
            
            <p><strong>Out-of-Scope Findings:</strong> {stats.get('out_of_scope_hosts', 0)} hosts were 
            discovered outside the defined scope, requiring investigation to ensure comprehensive coverage.</p>
            
            <p><strong>Security Implications:</strong> Each discovered host represents a potential attack vector. 
            Priority should be given to securing exposed services and ensuring proper network segmentation.</p>
        </div>
        """
        return summary
    
    @staticmethod
    def _generate_scan_executive_summary(data: Dict[str, Any]) -> str:
        """Generate executive summary for scan reports"""
        scan = data.get('scan', {})
        hosts = data.get('hosts', [])
        
        open_ports_count = sum(len([p for p in host.get('ports', []) if p.get('state') == 'open']) for host in hosts)
        
        summary = f"""
        <div class="executive-summary">
            <h3>Executive Summary</h3>
            <p><strong>Scan Overview:</strong> This {scan.get('tool_name', 'network')} scan 
            ({scan.get('filename', 'N/A')}) discovered {len(hosts)} active hosts with a total of 
            {open_ports_count} open ports across the target network.</p>
            
            <p><strong>Security Exposure:</strong> Each open port represents a potential entry point for 
            attackers. Critical services should be reviewed for necessity, proper configuration, and access controls.</p>
            
            <p><strong>Risk Assessment:</strong> Hosts with multiple open ports or common attack vectors 
            (SSH, RDP, web services) require immediate security review and hardening measures.</p>
        </div>
        """
        return summary
    
    @staticmethod
    def _generate_out_of_scope_summary(data: Dict[str, Any]) -> str:
        """Generate executive summary for out-of-scope reports"""
        total_findings = data.get('total_out_of_scope_hosts', 0)
        by_tool = data.get('findings_by_tool', {})
        
        summary = f"""
        <div class="executive-summary">
            <h3>Executive Summary</h3>
            <p><strong>Scope Verification:</strong> {total_findings} hosts were discovered outside 
            the defined project scope during network reconnaissance activities.</p>
            
            <p><strong>Discovery Sources:</strong> These findings originate from {len(by_tool)} different 
            scanning tools, indicating comprehensive coverage may have extended beyond intended boundaries.</p>
            
            <p><strong>Action Required:</strong> Out-of-scope discoveries should be reviewed to determine 
            if scope expansion is needed or if scanning parameters require adjustment for future assessments.</p>
        </div>
        """
        return summary
    
    @staticmethod
    def generate_recommendations(report_data: Dict[str, Any]) -> str:
        """Generate security recommendations based on report data"""
        recommendations = []
        
        # Generic network security recommendations
        recommendations.extend([
            "Implement network segmentation to limit lateral movement",
            "Regularly update and patch all discovered systems",
            "Deploy intrusion detection systems for continuous monitoring",
            "Conduct regular vulnerability assessments",
            "Implement proper access controls and authentication"
        ])
        
        # Report-specific recommendations
        if report_data.get('report_type') == 'scope_report':
            hosts = report_data.get('hosts', [])
            if any('22' in str(p.get('port_number', '')) for host in hosts for p in host.get('ports', [])):
                recommendations.append("Review SSH access and implement key-based authentication")
            if any('80' in str(p.get('port_number', '')) or '443' in str(p.get('port_number', '')) 
                   for host in hosts for p in host.get('ports', [])):
                recommendations.append("Audit web applications for security vulnerabilities")
        
        html = '<div class="recommendations"><h4>🔒 Security Recommendations</h4>'
        for i, rec in enumerate(recommendations[:8], 1):  # Limit to top 8
            html += f'<div class="recommendation-item">{i}. {rec}</div>'
        html += '</div>'
        
        return html
    
    @staticmethod
    def generate_professional_html_report(data: Dict[str, Any]) -> str:
        """Generate a comprehensive professional HTML report"""
        report_type = data.get('report_type', 'Network Report')
        generated_at = data.get('generated_at', datetime.utcnow().isoformat())
        
        # Header with logo and metadata
        header_section = f"""
        <div class="report-header">
            <div class="metadata">
                <div>
                    <div class="report-title">NetworkMapper Security Report</div>
                    <div class="report-subtitle">{report_type.replace('_', ' ').title()}</div>
                </div>
                <div>
                    <strong>Generated:</strong> {datetime.fromisoformat(generated_at.replace('Z', '')).strftime('%B %d, %Y at %I:%M %p')}<br>
                    <strong>Report ID:</strong> NM-{datetime.utcnow().strftime('%Y%m%d')}-{abs(hash(str(data)))%10000:04d}
                </div>
            </div>
        </div>
        """
        
        # Executive Summary
        executive_summary = ReportTemplates.generate_executive_summary(data)
        
        # Statistics Overview
        stats_section = ReportTemplates._generate_stats_section(data)
        
        # Main Content Sections
        content_sections = ReportTemplates._generate_content_sections(data)
        
        # Recommendations
        recommendations = ReportTemplates.generate_recommendations(data)
        
        # Footer
        footer = f"""
        <div class="footer">
            <p>This report was generated by NetworkMapper - Professional Network Discovery Platform</p>
            <p>© {datetime.utcnow().year} NetworkMapper. For questions about this report, 
            contact your security team or system administrator.</p>
        </div>
        """
        
        # Complete HTML
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>NetworkMapper Report - {report_type.replace('_', ' ').title()}</title>
            {ReportTemplates.get_css_styles()}
        </head>
        <body>
            {header_section}
            {executive_summary}
            {stats_section}
            {content_sections}
            {recommendations}
            {footer}
        </body>
        </html>
        """
        
        return html
    
    @staticmethod
    def _generate_stats_section(data: Dict[str, Any]) -> str:
        """Generate statistics overview section"""
        stats = data.get('statistics', {})
        
        if not stats:
            return ""
        
        stats_cards = []
        
        # Common stats for all report types
        if 'total_hosts' in stats:
            stats_cards.append(f'<div class="stat-card"><div class="stat-value">{stats["total_hosts"]}</div><div class="stat-label">Discovered Hosts</div></div>')
        if 'total_scans' in stats:
            stats_cards.append(f'<div class="stat-card"><div class="stat-value">{stats["total_scans"]}</div><div class="stat-label">Scans Analyzed</div></div>')
        if 'total_subnets' in stats:
            stats_cards.append(f'<div class="stat-card"><div class="stat-value">{stats["total_subnets"]}</div><div class="stat-label">Network Subnets</div></div>')
        if 'out_of_scope_hosts' in stats:
            stats_cards.append(f'<div class="stat-card"><div class="stat-value">{stats["out_of_scope_hosts"]}</div><div class="stat-label">Out-of-Scope</div></div>')
        
        if stats_cards:
            return f"""
            <div class="section">
                <div class="section-header">📊 Key Metrics</div>
                <div class="section-content">
                    <div class="stats-grid">
                        {"".join(stats_cards)}
                    </div>
                </div>
            </div>
            """
        return ""
    
    @staticmethod
    def _generate_content_sections(data: Dict[str, Any]) -> str:
        """Generate main content sections based on report type"""
        report_type = data.get('report_type', '')
        
        if report_type == 'scope_report':
            return ReportTemplates._generate_scope_content(data)
        elif report_type == 'scan_report':
            return ReportTemplates._generate_scan_content(data)
        elif report_type == 'out_of_scope_findings':
            return ReportTemplates._generate_out_of_scope_content(data)
        else:
            return ""
    
    @staticmethod
    def _generate_scope_content(data: Dict[str, Any]) -> str:
        """Generate scope-specific content sections"""
        content = ""
        
        # Subnet Information
        scope = data.get('scope', {})
        if scope.get('subnets'):
            content += """
            <div class="section">
                <div class="section-header">🌐 Network Subnets</div>
                <div class="section-content">
                    <table>
                        <thead>
                            <tr>
                                <th>CIDR Block</th>
                                <th>Description</th>
                                <th>Address Space</th>
                                <th>Network Type</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            
            for subnet in scope['subnets']:
                metrics = SubnetCalculator.calculate_subnet_metrics(subnet.get('cidr', ''))
                content += f"""
                <tr>
                    <td><code>{subnet.get('cidr', 'N/A')}</code></td>
                    <td>{subnet.get('description', 'No description')}</td>
                    <td>{metrics['usable_addresses']:,} usable ({metrics['total_addresses']:,} total)</td>
                    <td>{'Private' if metrics['is_private'] else 'Public'}</td>
                </tr>
                """
            
            content += "</tbody></table></div></div>"
        
        # Host Information
        hosts = data.get('hosts', [])
        if hosts:
            content += ReportTemplates._generate_hosts_table(hosts)
        
        # Out-of-scope hosts
        oos_hosts = data.get('out_of_scope_hosts', [])
        if oos_hosts:
            content += ReportTemplates._generate_out_of_scope_table(oos_hosts)
        
        return content
    
    @staticmethod
    def _generate_scan_content(data: Dict[str, Any]) -> str:
        """Generate scan-specific content sections"""
        content = ""
        
        # Scan Information
        scan = data.get('scan', {})
        content += f"""
        <div class="section">
            <div class="section-header">🔍 Scan Details</div>
            <div class="section-content">
                <table>
                    <tr><td><strong>Filename:</strong></td><td>{scan.get('filename', 'N/A')}</td></tr>
                    <tr><td><strong>Tool:</strong></td><td>{scan.get('tool_name', 'N/A')}</td></tr>
                    <tr><td><strong>Scan Type:</strong></td><td>{scan.get('scan_type', 'N/A')}</td></tr>
                    <tr><td><strong>Command Line:</strong></td><td><code>{scan.get('command_line', 'N/A')}</code></td></tr>
                    <tr><td><strong>Created:</strong></td><td>{scan.get('created_at', 'N/A')}</td></tr>
                </table>
            </div>
        </div>
        """
        
        # Host Results
        hosts = data.get('hosts', [])
        if hosts:
            content += ReportTemplates._generate_hosts_table(hosts)
        
        return content
    
    @staticmethod
    def _generate_out_of_scope_content(data: Dict[str, Any]) -> str:
        """Generate out-of-scope findings content"""
        findings_by_tool = data.get('findings_by_tool', {})
        
        content = ""
        for tool, findings in findings_by_tool.items():
            if findings:
                content += f"""
                <div class="section">
                    <div class="section-header">🔍 {tool.title()} Findings</div>
                    <div class="section-content">
                        <table>
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Hostname</th>
                                    <th>Ports</th>
                                    <th>Reason</th>
                                    <th>Found Date</th>
                                </tr>
                            </thead>
                            <tbody>
                """
                
                for finding in findings:
                    ports_info = json.dumps(finding.get('ports', {})) if finding.get('ports') else 'None'
                    content += f"""
                    <tr class="out-of-scope">
                        <td><code>{finding.get('ip_address', 'N/A')}</code></td>
                        <td>{finding.get('hostname', 'N/A')}</td>
                        <td><small>{ports_info}</small></td>
                        <td>{finding.get('reason', 'N/A')}</td>
                        <td>{finding.get('found_at', 'N/A')[:10] if finding.get('found_at') else 'N/A'}</td>
                    </tr>
                    """
                
                content += "</tbody></table></div></div>"
        
        return content
    
    @staticmethod
    def _generate_hosts_table(hosts: List[Dict]) -> str:
        """Generate hosts table section"""
        if not hosts:
            return ""
        
        content = """
        <div class="section">
            <div class="section-header">🖥️ Discovered Hosts</div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Operating System</th>
                            <th>Open Ports</th>
                            <th>Services</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for host in hosts[:50]:  # Limit to first 50 hosts for readability
            open_ports = [p for p in host.get('ports', []) if p.get('state') == 'open']
            ports_str = ', '.join([f"{p.get('port_number', '')}/{p.get('protocol', '')}" 
                                  for p in open_ports[:10]])  # Limit ports display
            
            services_str = ', '.join([p.get('service_name', 'unknown') 
                                    for p in open_ports[:5] if p.get('service_name')])
            
            content += f"""
            <tr>
                <td><code>{host.get('ip_address', 'N/A')}</code></td>
                <td>{host.get('hostname', 'N/A')}</td>
                <td>{host.get('os_name', 'Unknown')}</td>
                <td><small>{ports_str}</small></td>
                <td><small>{services_str}</small></td>
            </tr>
            """
        
        if len(hosts) > 50:
            content += f"<tr><td colspan='5'><em>... and {len(hosts) - 50} more hosts</em></td></tr>"
        
        content += "</tbody></table></div></div>"
        return content
    
    @staticmethod
    def _generate_out_of_scope_table(oos_hosts: List[Dict]) -> str:
        """Generate out-of-scope hosts table"""
        if not oos_hosts:
            return ""
        
        content = """
        <div class="section">
            <div class="section-header">⚠️ Out-of-Scope Hosts</div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Tool Source</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for host in oos_hosts:
            content += f"""
            <tr class="out-of-scope">
                <td><code>{host.get('ip_address', 'N/A')}</code></td>
                <td>{host.get('hostname', 'N/A')}</td>
                <td>{host.get('tool_source', 'N/A')}</td>
                <td>{host.get('reason', 'N/A')}</td>
            </tr>
            """
        
        content += "</tbody></table></div></div>"
        return content