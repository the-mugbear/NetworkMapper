"""
Hosts API v2 - Works with deduplicated host schema

This endpoint works with the new v2 schema that eliminates duplicates
at the database level, making the API much simpler and more efficient.
"""

from typing import List, Optional
import ipaddress
import json
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import or_, and_, distinct, func
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import Host as HostSchema

# Service port mappings (same as v1)
SERVICE_PORT_MAPPINGS = {
    # Web services
    'http': [80, 8000, 8080, 8081, 8008, 8888],
    'https': [443, 8443, 8444],
    'web': [80, 443, 8000, 8080, 8081, 8008, 8443, 8444, 8888],
    
    # Remote access
    'ssh': [22],
    'telnet': [23],
    'rdp': [3389],
    'vnc': [5900, 5901, 5902, 5903, 5904, 5905],
    
    # File transfer
    'ftp': [21, 20],
    'sftp': [22],
    'ftps': [990, 989],
    'tftp': [69],
    
    # Email
    'smtp': [25, 587, 465],
    'pop3': [110, 995],
    'imap': [143, 993],
    'mail': [25, 110, 143, 587, 465, 995, 993],
    
    # DNS
    'dns': [53],
    
    # Network management
    'snmp': [161, 162],
    'ntp': [123],
    'syslog': [514],
    
    # Databases
    'mysql': [3306],
    'postgresql': [5432],
    'postgres': [5432],
    'mssql': [1433],
    'sqlserver': [1433],
    'oracle': [1521],
    'mongodb': [27017],
    'redis': [6379],
    
    # Windows services
    'netbios': [137, 138, 139],
    'smb': [445, 139],
    'cifs': [445],
    'winrm': [5985, 5986],
    'rpc': [135],
    'ldap': [389, 636],
    'kerberos': [88],
    
    # Other common services
    'dhcp': [67, 68],
    'printer': [515, 631, 9100],
    'ipp': [631],
    'upnp': [1900],
    'sip': [5060, 5061],
    'rtsp': [554],
    'irc': [6667, 6697],
}

router = APIRouter()


@router.get("/", response_model=List[HostSchema])
def get_hosts_v2(
    state: Optional[str] = None,
    search: Optional[str] = None,
    ports: Optional[str] = Query(None, description="Comma-separated list of ports (e.g., '22,80,443')"),
    services: Optional[str] = Query(None, description="Comma-separated list of service names (e.g., 'ssh,http,https')"),
    port_states: Optional[str] = Query(None, description="Comma-separated list of port states (e.g., 'open,closed')"),
    has_open_ports: Optional[bool] = Query(None, description="Filter hosts that have any open ports"),
    os_filter: Optional[str] = Query(None, description="Filter by operating system"),
    subnets: Optional[str] = Query(None, description="Comma-separated list of subnet CIDRs (e.g., '192.168.1.0/24,10.0.0.0/8')"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Get hosts from v2 schema (deduplicated by IP).
    Much simpler than v1 since we don't need aggregation logic.
    """
    # Base query with eager loading
    query = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    )
    
    # Apply filters
    if state:
        query = query.filter(models.Host.state == state)
    
    if os_filter:
        query = query.filter(
            or_(
                models.Host.os_name.ilike(f'%{os_filter}%'),
                models.Host.os_family.ilike(f'%{os_filter}%')
            )
        )
    
    # Subnet filtering
    if subnets:
        subnet_conditions = _parse_subnets(subnets)
        if subnet_conditions:
            query = query.filter(or_(*subnet_conditions))
    
    # Port-based filters
    if ports or services or port_states or has_open_ports:
        # Use subquery to filter by port criteria
        port_subquery = db.query(models.Host.id).join(models.Port)
        
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            if port_list:
                port_subquery = port_subquery.filter(models.Port.port_number.in_(port_list))
        
        if services:
            service_list = [s.strip().lower() for s in services.split(',') if s.strip()]
            if service_list:
                service_conditions = [models.Port.service_name.ilike(f'%{service}%') for service in service_list]
                port_subquery = port_subquery.filter(or_(*service_conditions))
        
        if port_states:
            state_list = [s.strip().lower() for s in port_states.split(',') if s.strip()]
            if state_list:
                port_subquery = port_subquery.filter(models.Port.state.in_(state_list))
        
        if has_open_ports is not None:
            if has_open_ports:
                port_subquery = port_subquery.filter(models.Port.state == 'open')
            else:
                # Get hosts that don't have any open ports
                open_host_ids = db.query(models.Host.id).join(models.Port).filter(models.Port.state == 'open')
                query = query.filter(~models.Host.id.in_(open_host_ids))
                port_subquery = None  # Skip port subquery filter
        
        if port_subquery:
            query = query.filter(models.Host.id.in_(port_subquery))
    
    # Search functionality
    if search:
        host_search_conditions = [
            models.Host.ip_address.contains(search),
            models.Host.hostname.contains(search),
            models.Host.os_name.contains(search),
            models.Host.os_family.contains(search)
        ]
        
        # Port-based search
        search_lower = search.lower().strip()
        port_search_conditions = []
        
        if search.isdigit():
            port_search_conditions.append(models.Port.port_number == int(search))
        
        service_ports = SERVICE_PORT_MAPPINGS.get(search_lower)
        if service_ports:
            port_search_conditions.append(models.Port.port_number.in_(service_ports))
        
        if not search.isdigit():
            port_search_conditions.extend([
                models.Port.service_name.ilike(f'%{search}%'),
                models.Port.service_product.ilike(f'%{search}%')
            ])
        
        if port_search_conditions:
            search_port_subquery = db.query(models.Host.id).join(models.Port).filter(or_(*port_search_conditions))
            combined_search = or_(
                or_(*host_search_conditions),
                models.Host.id.in_(search_port_subquery)
            )
        else:
            combined_search = or_(*host_search_conditions)
        
        query = query.filter(combined_search)
    
    # Apply pagination and return
    hosts = query.offset(skip).limit(limit).all()
    return hosts


@router.get("/{host_id}", response_model=HostSchema)
def get_host_v2(host_id: int, db: Session = Depends(get_db)):
    """Get a specific host by ID"""
    host = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    ).filter(models.Host.id == host_id).first()
    
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host


@router.get("/filters/data")
def get_host_filter_data_v2(db: Session = Depends(get_db)):
    """Get available filter data for the frontend"""
    
    # Get most common ports
    common_ports = db.query(
        models.Port.port_number,
        models.Port.service_name,
        models.Port.state,
        func.count(models.Port.id).label('count')
    ).group_by(
        models.Port.port_number,
        models.Port.service_name,
        models.Port.state
    ).order_by(
        func.count(models.Port.id).desc()
    ).limit(100).all()
    
    # Get unique services
    services = db.query(
        models.Port.service_name,
        func.count(models.Port.id).label('count')
    ).filter(
        models.Port.service_name.isnot(None),
        models.Port.service_name != ''
    ).group_by(
        models.Port.service_name
    ).order_by(
        func.count(models.Port.id).desc()
    ).limit(50).all()
    
    # Get unique operating systems
    operating_systems = db.query(
        models.Host.os_name,
        func.count(models.Host.id).label('count')
    ).filter(
        models.Host.os_name.isnot(None),
        models.Host.os_name != ''
    ).group_by(
        models.Host.os_name
    ).order_by(
        func.count(models.Host.id).desc()
    ).limit(20).all()
    
    # Get subnets (from v1 schema since subnet management hasn't changed)
    subnets = db.query(
        models.Subnet.cidr,
        models.Scope.name.label('scope_name'),
        func.count(models.HostSubnetMapping.id).label('host_count')
    ).join(
        models.Scope, models.Subnet.scope_id == models.Scope.id
    ).outerjoin(
        models.HostSubnetMapping, models.Subnet.id == models.HostSubnetMapping.subnet_id
    ).group_by(
        models.Subnet.id, models.Subnet.cidr, models.Scope.name
    ).order_by(
        func.count(models.HostSubnetMapping.id).desc()
    ).limit(50).all()
    
    return {
        'common_ports': [
            {
                'port': port.port_number,
                'service': port.service_name or 'unknown',
                'state': port.state,
                'count': port.count
            }
            for port in common_ports
        ],
        'services': [
            {
                'name': service.service_name,
                'count': service.count
            }
            for service in services
        ],
        'operating_systems': [
            {
                'name': os.os_name,
                'count': os.count
            }
            for os in operating_systems
        ],
        'subnets': [
            {
                'cidr': subnet.cidr,
                'scope_name': subnet.scope_name,
                'host_count': subnet.host_count or 0
            }
            for subnet in subnets
        ]
    }


@router.get("/scan/{scan_id}", response_model=List[HostSchema])
def get_hosts_by_scan_v2(
    scan_id: int,
    state: Optional[str] = None,
    skip: int = 0,
    limit: int = 1000,
    db: Session = Depends(get_db)
):
    """
    Get hosts that were discovered in a specific scan.
    Uses HostScanHistory to find hosts associated with the scan.
    """
    # Check if scan exists
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Query hosts through HostScanHistory
    query = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    ).join(
        models.HostScanHistory, models.Host.id == models.HostScanHistory.host_id
    ).filter(
        models.HostScanHistory.scan_id == scan_id
    )
    
    # Apply state filter if provided
    if state:
        query = query.filter(models.Host.state == state)
    
    # Apply pagination and return
    hosts = query.offset(skip).limit(limit).all()
    return hosts


def _parse_subnets(subnet_str: str):
    """Helper function to parse subnet CIDR strings"""
    subnet_conditions = []
    subnets_list = [s.strip() for s in subnet_str.split(',') if s.strip()]
    
    for subnet_cidr in subnets_list:
        try:
            # Parse the subnet CIDR notation
            network = ipaddress.ip_network(subnet_cidr, strict=False)
            
            # For small networks, use direct IP matching
            # For large networks, use prefix matching
            if network.num_addresses <= 1000:
                ip_conditions = []
                for host_ip in network.hosts():
                    ip_conditions.append(models.Host.ip_address == str(host_ip))
                # Also include network and broadcast addresses
                ip_conditions.append(models.Host.ip_address == str(network.network_address))
                ip_conditions.append(models.Host.ip_address == str(network.broadcast_address))
                
                if ip_conditions:
                    subnet_conditions.append(or_(*ip_conditions))
            else:
                # For larger networks, use prefix matching
                network_prefix = str(network.network_address)
                prefix_parts = network_prefix.split('.')
                # Basic IPv4 prefix matching based on subnet size
                if network.prefixlen >= 24:  # /24 or smaller
                    prefix = '.'.join(prefix_parts[:3])
                    subnet_conditions.append(models.Host.ip_address.like(f'{prefix}.%'))
                elif network.prefixlen >= 16:  # /16 to /23
                    prefix = '.'.join(prefix_parts[:2])
                    subnet_conditions.append(models.Host.ip_address.like(f'{prefix}.%'))
                else:  # /8 to /15
                    prefix = prefix_parts[0]
                    subnet_conditions.append(models.Host.ip_address.like(f'{prefix}.%'))
                    
        except (ipaddress.AddressValueError, ValueError):
            # If subnet parsing fails, try to use it as a simple IP prefix
            subnet_conditions.append(models.Host.ip_address.like(f'{subnet_cidr}%'))
    
    return subnet_conditions if subnet_conditions else None


@router.get("/tool-ready/{format}")
def get_tool_ready_hosts(
    format: str,
    state: Optional[str] = None,
    search: Optional[str] = None,
    ports: Optional[str] = Query(None, description="Comma-separated list of ports (e.g., '22,80,443')"),
    services: Optional[str] = Query(None, description="Comma-separated list of service names (e.g., 'ssh,http,https')"),
    port_states: Optional[str] = Query(None, description="Comma-separated list of port states (e.g., 'open,closed')"),
    has_open_ports: Optional[bool] = Query(None, description="Filter hosts that have any open ports"),
    os_filter: Optional[str] = Query(None, description="Filter by operating system"),
    subnets: Optional[str] = Query(None, description="Comma-separated list of subnet CIDRs (e.g., '192.168.1.0/24,10.0.0.0/8')"),
    scan_id: Optional[int] = Query(None, description="Filter by specific scan ID"),
    include_ports: Optional[bool] = Query(False, description="Include port information in output"),
    db: Session = Depends(get_db)
):
    """
    Generate tool-ready output for filtered hosts.
    
    Supported formats:
    - ip-list: Simple list of IP addresses (one per line)
    - nmap: Nmap-compatible target list
    - metasploit: Metasploit RHOSTS format
    - masscan: Masscan target format
    - nuclei: Nuclei target format
    - host-port: IP:PORT format for each open port
    - json: JSON format with host details
    """
    
    # Validate format
    supported_formats = ['ip-list', 'nmap', 'metasploit', 'masscan', 'nuclei', 'host-port', 'json']
    if format not in supported_formats:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported format '{format}'. Supported formats: {', '.join(supported_formats)}"
        )
    
    # Base query (reuse the filtering logic from get_hosts_v2)
    query = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    )
    
    # Apply filters (same as get_hosts_v2)
    if state:
        query = query.filter(models.Host.state == state)
    
    if os_filter:
        query = query.filter(
            or_(
                models.Host.os_name.ilike(f'%{os_filter}%'),
                models.Host.os_family.ilike(f'%{os_filter}%')
            )
        )
    
    # Subnet filtering
    if subnets:
        subnet_conditions = _parse_subnets(subnets)
        if subnet_conditions:
            query = query.filter(or_(*subnet_conditions))
    
    # Scan ID filtering
    if scan_id:
        # Filter hosts that were discovered in this specific scan
        host_ids_in_scan = db.query(models.HostScanHistory.host_id).filter(
            models.HostScanHistory.scan_id == scan_id
        ).subquery()
        query = query.filter(models.Host.id.in_(host_ids_in_scan))
    
    # Port-based filters
    if ports or services or port_states or has_open_ports:
        # Use subquery to filter by port criteria
        port_subquery = db.query(models.Host.id).join(models.Port)
        
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            if port_list:
                port_subquery = port_subquery.filter(models.Port.port_number.in_(port_list))
        
        if services:
            service_names = [s.strip().lower() for s in services.split(',') if s.strip()]
            service_conditions = []
            
            for service in service_names:
                # Direct service name match
                service_conditions.append(models.Port.service_name.ilike(f'%{service}%'))
                
                # Port number mapping
                if service in SERVICE_PORT_MAPPINGS:
                    mapped_ports = SERVICE_PORT_MAPPINGS[service]
                    service_conditions.append(models.Port.port_number.in_(mapped_ports))
            
            if service_conditions:
                port_subquery = port_subquery.filter(or_(*service_conditions))
        
        if port_states:
            states = [s.strip() for s in port_states.split(',') if s.strip()]
            port_subquery = port_subquery.filter(models.Port.state.in_(states))
        
        if has_open_ports:
            port_subquery = port_subquery.filter(models.Port.state == 'open')
        
        # Apply the port filter to main query
        host_ids_with_ports = port_subquery.distinct().subquery()
        query = query.filter(models.Host.id.in_(host_ids_with_ports))
    
    # Search filter
    if search:
        query = query.filter(
            or_(
                models.Host.ip_address.ilike(f'%{search}%'),
                models.Host.hostname.ilike(f'%{search}%'),
                models.Host.os_name.ilike(f'%{search}%')
            )
        )
    
    # Execute query
    hosts = query.all()
    
    # Generate output based on format
    output = _generate_tool_output(hosts, format, include_ports)
    
    # Set appropriate content type and filename
    content_type, filename = _get_content_type_and_filename(format)
    
    return Response(
        content=output,
        media_type=content_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


def _generate_tool_output(hosts: List[models.Host], format: str, include_ports: bool = False) -> str:
    """Generate tool-specific output format"""
    
    if format == 'ip-list':
        # Simple list of IP addresses
        return '\n'.join([host.ip_address for host in hosts])
    
    elif format == 'nmap':
        # Nmap-compatible target list (space-separated)
        return ' '.join([host.ip_address for host in hosts])
    
    elif format == 'metasploit':
        # Metasploit RHOSTS format (space-separated)
        return ' '.join([host.ip_address for host in hosts])
    
    elif format == 'masscan':
        # Masscan target format (comma-separated)
        return ','.join([host.ip_address for host in hosts])
    
    elif format == 'nuclei':
        # Nuclei target format - URLs for web services, IPs for others
        targets = []
        for host in hosts:
            # Check if host has web ports
            web_ports = []
            if include_ports:
                for port in host.ports:
                    if port.state == 'open' and port.port_number in [80, 443, 8000, 8080, 8081, 8008, 8443, 8444, 8888]:
                        web_ports.append(port.port_number)
            
            if web_ports:
                # Generate URLs for web ports
                for port_num in web_ports:
                    protocol = 'https' if port_num in [443, 8443, 8444] else 'http'
                    if port_num in [80, 443]:
                        targets.append(f"{protocol}://{host.ip_address}")
                    else:
                        targets.append(f"{protocol}://{host.ip_address}:{port_num}")
            else:
                # Just add IP for non-web hosts
                targets.append(host.ip_address)
        
        return '\n'.join(targets)
    
    elif format == 'host-port':
        # IP:PORT format for each open port
        results = []
        for host in hosts:
            open_ports = [port for port in host.ports if port.state == 'open']
            if open_ports:
                for port in open_ports:
                    results.append(f"{host.ip_address}:{port.port_number}")
            else:
                # Include hosts without open ports as just IP
                results.append(host.ip_address)
        
        return '\n'.join(results)
    
    elif format == 'json':
        # JSON format with host details
        host_data = []
        for host in hosts:
            host_info = {
                'ip_address': host.ip_address,
                'hostname': host.hostname,
                'state': host.state,
                'os_name': host.os_name,
                'os_family': host.os_family
            }
            
            if include_ports:
                host_info['ports'] = [
                    {
                        'port': port.port_number,
                        'protocol': port.protocol,
                        'state': port.state,
                        'service': port.service_name,
                        'product': port.service_product,
                        'version': port.service_version
                    }
                    for port in host.ports
                ]
            
            host_data.append(host_info)
        
        return json.dumps(host_data, indent=2)
    
    else:
        return '\n'.join([host.ip_address for host in hosts])


def _get_content_type_and_filename(format: str) -> tuple:
    """Get content type and filename for different formats"""
    
    format_config = {
        'ip-list': ('text/plain', 'hosts.txt'),
        'nmap': ('text/plain', 'nmap-targets.txt'),
        'metasploit': ('text/plain', 'msf-targets.txt'),
        'masscan': ('text/plain', 'masscan-targets.txt'),
        'nuclei': ('text/plain', 'nuclei-targets.txt'),
        'host-port': ('text/plain', 'host-ports.txt'),
        'json': ('application/json', 'hosts.json')
    }
    
    return format_config.get(format, ('text/plain', 'hosts.txt'))