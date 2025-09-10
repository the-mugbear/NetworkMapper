from typing import List, Optional
import ipaddress
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import or_, and_, distinct, func
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import Host

# Common service name to port mappings for enhanced search
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
    'sftp': [22],  # Usually runs over SSH
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

@router.get("/", response_model=List[Host])
def get_hosts(
    scan_id: Optional[int] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    ports: Optional[str] = Query(None, description="Comma-separated list of ports (e.g., '22,80,443')"),
    services: Optional[str] = Query(None, description="Comma-separated list of service names (e.g., 'ssh,http,https')"),
    port_states: Optional[str] = Query(None, description="Comma-separated list of port states (e.g., 'open,closed')"),
    has_open_ports: Optional[bool] = Query(None, description="Filter hosts that have any open ports"),
    os_filter: Optional[str] = Query(None, description="Filter by operating system"),
    subnet: Optional[str] = Query(None, description="Filter by subnet CIDR (e.g., '192.168.1.0/24')"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    ).distinct()
    
    # Track if we need to join with ports table
    needs_port_join = bool(ports or services or port_states or has_open_ports)
    
    if needs_port_join:
        query = query.join(models.Port, models.Host.id == models.Port.host_id)
    
    # Filter by scan_id if provided
    if scan_id:
        query = query.filter(models.Host.scan_id == scan_id)
    
    # Filter by state if provided
    if state:
        query = query.filter(models.Host.state == state)
    
    # Filter by operating system if provided
    if os_filter:
        query = query.filter(
            or_(
                models.Host.os_name.ilike(f'%{os_filter}%'),
                models.Host.os_family.ilike(f'%{os_filter}%')
            )
        )
    
    # Filter by subnet if provided
    if subnet:
        try:
            # Parse the subnet CIDR notation
            network = ipaddress.ip_network(subnet, strict=False)
            
            # Get all IP addresses in the network range
            ip_conditions = []
            for host_ip in network.hosts():
                ip_conditions.append(models.Host.ip_address == str(host_ip))
            
            # For small networks, use direct IP matching
            # For large networks, use prefix matching
            if network.num_addresses <= 1000:
                if ip_conditions:
                    query = query.filter(or_(*ip_conditions))
            else:
                # For larger networks, use prefix matching as fallback
                network_prefix = str(network.network_address)
                prefix_len = len(network_prefix.split('.')[0])  # Basic IPv4 prefix matching
                query = query.filter(models.Host.ip_address.like(f'{network_prefix.split(".")[0]}.%'))
                
        except (ipaddress.AddressValueError, ValueError):
            # If subnet parsing fails, try to use it as a simple IP prefix
            query = query.filter(models.Host.ip_address.like(f'{subnet}%'))
    
    # Port-based filters
    if ports:
        port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
        if port_list:
            query = query.filter(models.Port.port_number.in_(port_list))
    
    if services:
        service_list = [s.strip().lower() for s in services.split(',') if s.strip()]
        if service_list:
            service_conditions = [models.Port.service_name.ilike(f'%{service}%') for service in service_list]
            query = query.filter(or_(*service_conditions))
    
    if port_states:
        state_list = [s.strip().lower() for s in port_states.split(',') if s.strip()]
        if state_list:
            query = query.filter(models.Port.state.in_(state_list))
    
    if has_open_ports is not None:
        if has_open_ports:
            if not needs_port_join:
                query = query.join(models.Port, models.Host.id == models.Port.host_id)
            query = query.filter(models.Port.state == 'open')
        else:
            # Hosts with no open ports - this is more complex
            subquery = db.query(models.Host.id).join(models.Port).filter(models.Port.state == 'open')
            query = query.filter(~models.Host.id.in_(subquery))
    
    # Search functionality - enhanced to include ports and services
    if search:
        search_conditions = [
            models.Host.ip_address.contains(search),
            models.Host.hostname.contains(search),
            models.Host.os_name.contains(search),
            models.Host.os_family.contains(search)
        ]
        
        search_lower = search.lower().strip()
        
        # Check if search term is numeric (could be a port number)
        if search.isdigit():
            # Join with ports table if not already joined for port number search
            if not needs_port_join:
                query = query.join(models.Port, models.Host.id == models.Port.host_id)
            search_conditions.append(models.Port.port_number == int(search))
        
        # Check if search term matches a known service name
        service_ports = SERVICE_PORT_MAPPINGS.get(search_lower)
        port_join_needed = False
        
        if service_ports:
            # Join with ports table if not already joined
            if not needs_port_join:
                query = query.join(models.Port, models.Host.id == models.Port.host_id)
                port_join_needed = True
            # Add condition to search for any of the mapped ports
            search_conditions.append(models.Port.port_number.in_(service_ports))
        
        # Check if search term could be a service name (for partial matches or unmapped services)
        if not search.isdigit():
            # Join with ports table if not already joined for service search
            if not needs_port_join and not port_join_needed:
                query = query.join(models.Port, models.Host.id == models.Port.host_id, isouter=True)
            
            search_conditions.extend([
                models.Port.service_name.ilike(f'%{search}%'),
                models.Port.service_product.ilike(f'%{search}%')
            ])
        
        query = query.filter(or_(*search_conditions))
    
    hosts = query.offset(skip).limit(limit).all()
    return hosts

@router.get("/{host_id}", response_model=Host)
def get_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    ).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host

@router.get("/scan/{scan_id}", response_model=List[Host])
def get_hosts_by_scan(
    scan_id: int,
    state: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get hosts for a specific scan with pagination for performance"""
    query = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    ).filter(models.Host.scan_id == scan_id)
    
    if state:
        query = query.filter(models.Host.state == state)
    
    # Order by IP address for consistent pagination
    query = query.order_by(models.Host.ip_address)
    
    hosts = query.offset(skip).limit(limit).all()
    return hosts

@router.get("/filters/ports")
def get_available_ports(db: Session = Depends(get_db)):
    """Get list of available ports and services for filtering"""
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
        ]
    }