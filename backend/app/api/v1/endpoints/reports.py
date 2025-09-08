from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import or_, and_, distinct, func
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import Host
import io
import csv
import json
from datetime import datetime
import html

router = APIRouter()

class ReportGenerator:
    def __init__(self, db: Session):
        self.db = db
    
    def get_hosts_for_report(self, filters: Dict[str, Any]) -> List[models.Host]:
        """Get hosts based on filter parameters"""
        query = self.db.query(models.Host).options(
            selectinload(models.Host.ports).selectinload(models.Port.scripts),
            selectinload(models.Host.host_scripts),
            selectinload(models.Host.scan)
        ).distinct()
        
        # Apply the same filtering logic as the hosts endpoint
        needs_port_join = bool(filters.get('ports') or filters.get('services') or 
                              filters.get('port_states') or filters.get('has_open_ports'))
        
        if needs_port_join:
            query = query.join(models.Port, models.Host.id == models.Port.host_id)
        
        # Apply filters
        if filters.get('scan_id'):
            query = query.filter(models.Host.scan_id == filters['scan_id'])
        
        if filters.get('state'):
            query = query.filter(models.Host.state == filters['state'])
        
        if filters.get('os_filter'):
            query = query.filter(
                or_(
                    models.Host.os_name.ilike(f'%{filters["os_filter"]}%'),
                    models.Host.os_family.ilike(f'%{filters["os_filter"]}%')
                )
            )
        
        if filters.get('ports'):
            port_list = [int(p.strip()) for p in filters['ports'].split(',') if p.strip().isdigit()]
            if port_list:
                query = query.filter(models.Port.port_number.in_(port_list))
        
        if filters.get('services'):
            service_list = [s.strip().lower() for s in filters['services'].split(',') if s.strip()]
            if service_list:
                service_conditions = [models.Port.service_name.ilike(f'%{service}%') for service in service_list]
                query = query.filter(or_(*service_conditions))
        
        if filters.get('port_states'):
            state_list = [s.strip().lower() for s in filters['port_states'].split(',') if s.strip()]
            if state_list:
                query = query.filter(models.Port.state.in_(state_list))
        
        if filters.get('has_open_ports') is not None:
            if filters['has_open_ports']:
                if not needs_port_join:
                    query = query.join(models.Port, models.Host.id == models.Port.host_id)
                query = query.filter(models.Port.state == 'open')
        
        if filters.get('search'):
            search = filters['search']
            search_conditions = [
                models.Host.ip_address.contains(search),
                models.Host.hostname.contains(search),
                models.Host.os_name.contains(search),
                models.Host.os_family.contains(search)
            ]
            
            if search.isdigit():
                if not needs_port_join:
                    query = query.join(models.Port, models.Host.id == models.Port.host_id)
                search_conditions.append(models.Port.port_number == int(search))
            
            if not search.isdigit() or len(search) > 5:
                if not needs_port_join and search.isdigit():
                    query = query.join(models.Port, models.Host.id == models.Port.host_id)
                elif not needs_port_join:
                    query = query.join(models.Port, models.Host.id == models.Port.host_id, isouter=True)
                
                search_conditions.extend([
                    models.Port.service_name.ilike(f'%{search}%'),
                    models.Port.service_product.ilike(f'%{search}%')
                ])
            
            query = query.filter(or_(*search_conditions))
        
        return query.all()
    
    def generate_csv_report(self, hosts: List[models.Host]) -> str:
        """Generate CSV report from hosts data"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow([
            'IP Address', 'Hostname', 'State', 'OS Name', 'OS Family', 'OS Type', 'OS Accuracy',
            'Open Ports', 'Total Ports', 'Services', 'Scan File', 'Scan Date'
        ])
        
        for host in hosts:
            open_ports = [p for p in (host.ports or []) if p.state == 'open']
            total_ports = len(host.ports or [])
            
            # Get unique services
            services = list(set([p.service_name for p in open_ports if p.service_name]))
            services_str = ', '.join(services[:5])  # Limit to 5 services
            if len(services) > 5:
                services_str += f' (+{len(services) - 5} more)'
            
            # Open ports string
            open_ports_str = ', '.join([f"{p.port_number}/{p.protocol}" for p in open_ports[:10]])
            if len(open_ports) > 10:
                open_ports_str += f' (+{len(open_ports) - 10} more)'
            
            writer.writerow([
                host.ip_address,
                host.hostname or '',
                host.state or '',
                host.os_name or '',
                host.os_family or '',
                host.os_type or '',
                host.os_accuracy or '',
                open_ports_str,
                total_ports,
                services_str,
                host.scan.filename if host.scan else '',
                host.scan.created_at.strftime('%Y-%m-%d %H:%M:%S') if host.scan and host.scan.created_at else ''
            ])
        
        return output.getvalue()
    
    def generate_html_report(self, hosts: List[models.Host], filters: Dict[str, Any]) -> str:
        """Generate HTML report from hosts data"""
        # Calculate summary statistics
        total_hosts = len(hosts)
        hosts_up = len([h for h in hosts if h.state == 'up'])
        total_open_ports = sum(len([p for p in (h.ports or []) if p.state == 'open']) for h in hosts)
        
        # Get most common services
        service_count = {}
        for host in hosts:
            for port in (host.ports or []):
                if port.state == 'open' and port.service_name:
                    service_count[port.service_name] = service_count.get(port.service_name, 0) + 1
        
        top_services = sorted(service_count.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Get OS distribution
        os_count = {}
        for host in hosts:
            if host.os_name:
                os_count[host.os_name] = os_count.get(host.os_name, 0) + 1
        
        top_os = sorted(os_count.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Generate HTML
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>NetworkMapper Host Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .stat-box {{ background: #e3f2fd; padding: 15px; border-radius: 5px; text-align: center; flex: 1; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #1976d2; }}
        .stat-label {{ color: #666; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .host-row:nth-child(even) {{ background-color: #f9f9f9; }}
        .port-list {{ max-width: 200px; word-wrap: break-word; }}
        .service-list {{ max-width: 150px; word-wrap: break-word; }}
        .up {{ color: #4caf50; }}
        .down {{ color: #f44336; }}
        .charts {{ display: flex; gap: 30px; margin-bottom: 30px; }}
        .chart {{ flex: 1; }}
        .chart h3 {{ border-bottom: 2px solid #1976d2; padding-bottom: 5px; }}
        .bar {{ display: flex; align-items: center; margin-bottom: 5px; }}
        .bar-label {{ width: 150px; font-size: 0.9em; }}
        .bar-fill {{ height: 20px; background: #1976d2; margin: 0 10px; border-radius: 3px; }}
        .bar-value {{ font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>NetworkMapper Host Report</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        {self._format_filters_html(filters)}
    </div>
    
    <div class="summary">
        <div class="stat-box">
            <div class="stat-number">{total_hosts}</div>
            <div class="stat-label">Total Hosts</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{hosts_up}</div>
            <div class="stat-label">Hosts Up</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{total_open_ports}</div>
            <div class="stat-label">Open Ports</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{len(service_count)}</div>
            <div class="stat-label">Unique Services</div>
        </div>
    </div>
    
    <div class="charts">
        <div class="chart">
            <h3>Top Services</h3>
            {self._generate_chart_bars(top_services, max(dict(top_services).values()) if top_services else 1)}
        </div>
        <div class="chart">
            <h3>Top Operating Systems</h3>
            {self._generate_chart_bars(top_os, max(dict(top_os).values()) if top_os else 1)}
        </div>
    </div>
    
    <h2>Host Details</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>State</th>
                <th>OS</th>
                <th>Open Ports</th>
                <th>Services</th>
                <th>Scan</th>
            </tr>
        </thead>
        <tbody>
            {self._generate_host_rows_html(hosts)}
        </tbody>
    </table>
</body>
</html>"""
        return html_content
    
    def _format_filters_html(self, filters: Dict[str, Any]) -> str:
        """Format applied filters for HTML report"""
        if not filters:
            return "<p>No filters applied</p>"
        
        filter_items = []
        for key, value in filters.items():
            if value:
                if key == 'search':
                    filter_items.append(f"Search: {html.escape(str(value))}")
                elif key == 'state':
                    filter_items.append(f"Host State: {html.escape(str(value))}")
                elif key == 'ports':
                    filter_items.append(f"Ports: {html.escape(str(value))}")
                elif key == 'services':
                    filter_items.append(f"Services: {html.escape(str(value))}")
                elif key == 'os_filter':
                    filter_items.append(f"OS Filter: {html.escape(str(value))}")
        
        if filter_items:
            return f"<p><strong>Applied Filters:</strong> {', '.join(filter_items)}</p>"
        return "<p>No filters applied</p>"
    
    def _generate_chart_bars(self, data: List[tuple], max_value: int) -> str:
        """Generate HTML bars for charts"""
        if not data:
            return "<p>No data available</p>"
        
        bars = []
        for name, count in data[:10]:  # Top 10
            percentage = (count / max_value) * 100 if max_value > 0 else 0
            bars.append(f"""
                <div class="bar">
                    <div class="bar-label">{html.escape(str(name))}</div>
                    <div class="bar-fill" style="width: {percentage}%;"></div>
                    <div class="bar-value">{count}</div>
                </div>
            """)
        
        return ''.join(bars)
    
    def _generate_host_rows_html(self, hosts: List[models.Host]) -> str:
        """Generate HTML table rows for hosts"""
        rows = []
        for host in hosts:
            open_ports = [p for p in (host.ports or []) if p.state == 'open']
            services = list(set([p.service_name for p in open_ports if p.service_name]))
            
            open_ports_str = ', '.join([f"{p.port_number}" for p in open_ports[:10]])
            if len(open_ports) > 10:
                open_ports_str += f' (+{len(open_ports) - 10})'
            
            services_str = ', '.join(services[:5])
            if len(services) > 5:
                services_str += f' (+{len(services) - 5})'
            
            state_class = 'up' if host.state == 'up' else 'down'
            
            rows.append(f"""
                <tr class="host-row">
                    <td>{html.escape(host.ip_address)}</td>
                    <td>{html.escape(host.hostname or '')}</td>
                    <td class="{state_class}">{html.escape(host.state or '')}</td>
                    <td>{html.escape(host.os_name or '')}</td>
                    <td class="port-list">{html.escape(open_ports_str)}</td>
                    <td class="service-list">{html.escape(services_str)}</td>
                    <td>{html.escape(host.scan.filename if host.scan else '')}</td>
                </tr>
            """)
        
        return ''.join(rows)
    
    def generate_json_report(self, hosts: List[models.Host]) -> Dict[str, Any]:
        """Generate JSON report from hosts data"""
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_hosts": len(hosts),
                "hosts_up": len([h for h in hosts if h.state == 'up']),
                "hosts_down": len([h for h in hosts if h.state == 'down']),
                "total_open_ports": sum(len([p for p in (h.ports or []) if p.state == 'open']) for h in hosts)
            },
            "hosts": []
        }
        
        for host in hosts:
            host_data = {
                "id": host.id,
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "state": host.state,
                "os_info": {
                    "name": host.os_name,
                    "family": host.os_family,
                    "type": host.os_type,
                    "vendor": host.os_vendor,
                    "accuracy": host.os_accuracy
                },
                "ports": [],
                "scan_info": {
                    "filename": host.scan.filename if host.scan else None,
                    "scan_date": host.scan.created_at.isoformat() if host.scan and host.scan.created_at else None
                }
            }
            
            for port in (host.ports or []):
                port_data = {
                    "port_number": port.port_number,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": {
                        "name": port.service_name,
                        "product": port.service_product,
                        "version": port.service_version
                    }
                }
                host_data["ports"].append(port_data)
            
            report_data["hosts"].append(host_data)
        
        return report_data

@router.get("/hosts/csv")
def generate_hosts_csv_report(
    scan_id: Optional[int] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    ports: Optional[str] = None,
    services: Optional[str] = None,
    port_states: Optional[str] = None,
    has_open_ports: Optional[bool] = None,
    os_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Generate CSV report of hosts based on filters"""
    filters = {k: v for k, v in {
        'scan_id': scan_id,
        'state': state,
        'search': search,
        'ports': ports,
        'services': services,
        'port_states': port_states,
        'has_open_ports': has_open_ports,
        'os_filter': os_filter
    }.items() if v is not None}
    
    generator = ReportGenerator(db)
    hosts = generator.get_hosts_for_report(filters)
    csv_content = generator.generate_csv_report(hosts)
    
    filename = f"hosts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/hosts/html")
def generate_hosts_html_report(
    scan_id: Optional[int] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    ports: Optional[str] = None,
    services: Optional[str] = None,
    port_states: Optional[str] = None,
    has_open_ports: Optional[bool] = None,
    os_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Generate HTML report of hosts based on filters"""
    filters = {k: v for k, v in {
        'scan_id': scan_id,
        'state': state,
        'search': search,
        'ports': ports,
        'services': services,
        'port_states': port_states,
        'has_open_ports': has_open_ports,
        'os_filter': os_filter
    }.items() if v is not None}
    
    generator = ReportGenerator(db)
    hosts = generator.get_hosts_for_report(filters)
    html_content = generator.generate_html_report(hosts, filters)
    
    filename = f"hosts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/hosts/json")
def generate_hosts_json_report(
    scan_id: Optional[int] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    ports: Optional[str] = None,
    services: Optional[str] = None,
    port_states: Optional[str] = None,
    has_open_ports: Optional[bool] = None,
    os_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Generate JSON report of hosts based on filters"""
    filters = {k: v for k, v in {
        'scan_id': scan_id,
        'state': state,
        'search': search,
        'ports': ports,
        'services': services,
        'port_states': port_states,
        'has_open_ports': has_open_ports,
        'os_filter': os_filter
    }.items() if v is not None}
    
    generator = ReportGenerator(db)
    hosts = generator.get_hosts_for_report(filters)
    report_data = generator.generate_json_report(hosts)
    
    filename = f"hosts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    return Response(
        content=json.dumps(report_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )