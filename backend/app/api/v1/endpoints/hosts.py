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
    subnets: Optional[str] = Query(None, description="Comma-separated list of subnet CIDRs (e.g., '192.168.1.0/24,10.0.0.0/8')"),
    aggregate_by_ip: Optional[bool] = Query(True, description="Aggregate hosts by IP address across scans (default: true)"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    if aggregate_by_ip:
        return _get_aggregated_hosts_by_ip(
            db, scan_id, state, search, ports, services, port_states, 
            has_open_ports, os_filter, subnet, subnets, skip, limit
        )
    else:
        return _get_individual_hosts(
            db, scan_id, state, search, ports, services, port_states,
            has_open_ports, os_filter, subnet, subnets, skip, limit
        )


def _get_individual_hosts(
    db: Session, scan_id: Optional[int], state: Optional[str], search: Optional[str],
    ports: Optional[str], services: Optional[str], port_states: Optional[str],
    has_open_ports: Optional[bool], os_filter: Optional[str], subnet: Optional[str],
    subnets: Optional[str], skip: int, limit: int
):
    """Original implementation for individual host records (one per scan)"""
    # Track if we need to join with ports table
    needs_port_join = bool(ports or services or port_states or has_open_ports)
    
    # Build base query - if we need port joins, we'll use a subquery approach to avoid duplicates
    if needs_port_join:
        # First, get the host IDs that match port criteria
        port_subquery = db.query(models.Host.id).join(models.Port, models.Host.id == models.Port.host_id)
    else:
        port_subquery = None
    
    # Main query always starts with Host table
    query = db.query(models.Host).options(
        selectinload(models.Host.ports).selectinload(models.Port.scripts),
        selectinload(models.Host.host_scripts)
    )
    
    # Filter by scan_id if provided
    if scan_id:
        query = query.filter(models.Host.scan_id == scan_id)
        if port_subquery is not None:
            port_subquery = port_subquery.filter(models.Host.scan_id == scan_id)
    
    # Filter by state if provided
    if state:
        query = query.filter(models.Host.state == state)
        if port_subquery is not None:
            port_subquery = port_subquery.filter(models.Host.state == state)
    
    # Filter by operating system if provided
    if os_filter:
        os_conditions = or_(
            models.Host.os_name.ilike(f'%{os_filter}%'),
            models.Host.os_family.ilike(f'%{os_filter}%')
        )
        query = query.filter(os_conditions)
        if port_subquery is not None:
            port_subquery = port_subquery.filter(os_conditions)
    
    # Filter by subnet(s) if provided
    subnet_conditions = None
    if subnets:
        subnet_conditions = _parse_subnets(subnets)
    elif subnet:
        subnet_conditions = _parse_subnets(subnet)
    
    if subnet_conditions:
        subnet_filter = or_(*subnet_conditions)
        query = query.filter(subnet_filter)
        if port_subquery is not None:
            port_subquery = port_subquery.filter(subnet_filter)
    
    # Port-based filters - apply to port_subquery
    if port_subquery is not None:
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
                # For hosts with no open ports, we'll handle this differently
                open_hosts_subquery = db.query(models.Host.id).join(models.Port).filter(models.Port.state == 'open')
                query = query.filter(~models.Host.id.in_(open_hosts_subquery))
                port_subquery = None  # Skip the port subquery filter
        
        # Apply port subquery filter to main query
        if port_subquery is not None:
            query = query.filter(models.Host.id.in_(port_subquery))
    else:
        # Handle has_open_ports when no other port filters are specified
        if has_open_ports is not None:
            if has_open_ports:
                open_hosts_subquery = db.query(models.Host.id).join(models.Port).filter(models.Port.state == 'open')
                query = query.filter(models.Host.id.in_(open_hosts_subquery))
            else:
                open_hosts_subquery = db.query(models.Host.id).join(models.Port).filter(models.Port.state == 'open')
                query = query.filter(~models.Host.id.in_(open_hosts_subquery))
    
    # Search functionality - enhanced to include ports and services
    if search:
        host_search_conditions = [
            models.Host.ip_address.contains(search),
            models.Host.hostname.contains(search),
            models.Host.os_name.contains(search),
            models.Host.os_family.contains(search)
        ]
        
        search_lower = search.lower().strip()
        port_search_conditions = []
        
        # Check if search term is numeric (could be a port number)
        if search.isdigit():
            port_search_conditions.append(models.Port.port_number == int(search))
        
        # Check if search term matches a known service name
        service_ports = SERVICE_PORT_MAPPINGS.get(search_lower)
        if service_ports:
            port_search_conditions.append(models.Port.port_number.in_(service_ports))
        
        # Check if search term could be a service name (for partial matches or unmapped services)
        if not search.isdigit():
            port_search_conditions.extend([
                models.Port.service_name.ilike(f'%{search}%'),
                models.Port.service_product.ilike(f'%{search}%')
            ])
        
        # If we have port-related search conditions, create a subquery
        if port_search_conditions:
            search_port_subquery = db.query(models.Host.id).join(models.Port).filter(or_(*port_search_conditions))
            # Combine host and port search conditions
            combined_search = or_(
                or_(*host_search_conditions),
                models.Host.id.in_(search_port_subquery)
            )
        else:
            combined_search = or_(*host_search_conditions)
        
        query = query.filter(combined_search)
    
    hosts = query.offset(skip).limit(limit).all()
    return hosts


def _get_aggregated_hosts_by_ip(
    db: Session, scan_id: Optional[int], state: Optional[str], search: Optional[str],
    ports: Optional[str], services: Optional[str], port_states: Optional[str],
    has_open_ports: Optional[bool], os_filter: Optional[str], subnet: Optional[str],
    subnets: Optional[str], skip: int, limit: int
):
    """Aggregate hosts by IP address across all scans, combining ports from all scans"""
    from sqlalchemy import func
    from app.schemas.schemas import Port as PortSchema, Script as ScriptSchema, HostScript as HostScriptSchema
    
    # First, get unique IP addresses that match our criteria
    ip_query = db.query(models.Host.ip_address).distinct()
    
    # Apply basic host filters
    if scan_id:
        ip_query = ip_query.filter(models.Host.scan_id == scan_id)
    if state:
        ip_query = ip_query.filter(models.Host.state == state)
    if os_filter:
        ip_query = ip_query.filter(
            or_(
                models.Host.os_name.ilike(f'%{os_filter}%'),
                models.Host.os_family.ilike(f'%{os_filter}%')
            )
        )
    
    # Apply subnet filters
    subnet_conditions = None
    if subnets:
        subnet_conditions = _parse_subnets(subnets)
    elif subnet:
        subnet_conditions = _parse_subnets(subnet)
    
    if subnet_conditions:
        ip_query = ip_query.filter(or_(*subnet_conditions))
    
    # Apply port-based filters
    if ports or services or port_states or has_open_ports:
        ip_query = ip_query.join(models.Port)
        
        if ports:
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            if port_list:
                ip_query = ip_query.filter(models.Port.port_number.in_(port_list))
        
        if services:
            service_list = [s.strip().lower() for s in services.split(',') if s.strip()]
            if service_list:
                service_conditions = [models.Port.service_name.ilike(f'%{service}%') for service in service_list]
                ip_query = ip_query.filter(or_(*service_conditions))
        
        if port_states:
            state_list = [s.strip().lower() for s in port_states.split(',') if s.strip()]
            if state_list:
                ip_query = ip_query.filter(models.Port.state.in_(state_list))
        
        if has_open_ports is not None:
            if has_open_ports:
                ip_query = ip_query.filter(models.Port.state == 'open')
            else:
                # Get IPs that don't have any open ports
                open_ips = db.query(models.Host.ip_address).distinct().join(models.Port).filter(models.Port.state == 'open')
                ip_query = ip_query.filter(~models.Host.ip_address.in_(open_ips))
    
    # Apply search filters
    if search:
        host_search_conditions = [
            models.Host.ip_address.contains(search),
            models.Host.hostname.contains(search),
            models.Host.os_name.contains(search),
            models.Host.os_family.contains(search)
        ]
        
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
            search_port_ips = db.query(models.Host.ip_address).distinct().join(models.Port).filter(or_(*port_search_conditions))
            combined_search = or_(
                or_(*host_search_conditions),
                models.Host.ip_address.in_(search_port_ips)
            )
        else:
            combined_search = or_(*host_search_conditions)
        
        ip_query = ip_query.filter(combined_search)
    
    # Get the unique IP addresses with pagination
    ip_addresses = [result.ip_address for result in ip_query.offset(skip).limit(limit).all()]
    
    # Now build aggregated host objects for each IP
    aggregated_hosts = []
    for ip_address in ip_addresses:
        # Get the most recent host record for this IP (for metadata)
        base_host = db.query(models.Host).filter(
            models.Host.ip_address == ip_address
        ).order_by(models.Host.id.desc()).first()
        
        if not base_host:
            continue
        
        # Get all ports for this IP across all scans
        all_ports = db.query(models.Port).join(models.Host).filter(
            models.Host.ip_address == ip_address
        ).options(
            selectinload(models.Port.scripts)
        ).all()
        
        # Get all host scripts for this IP across all scans  
        all_host_scripts = db.query(models.HostScript).join(models.Host).filter(
            models.Host.ip_address == ip_address
        ).all()
        
        # Create aggregated host object
        aggregated_host = models.Host(
            id=base_host.id,
            scan_id=base_host.scan_id,  # Use most recent scan_id
            ip_address=ip_address,
            hostname=base_host.hostname,
            state=base_host.state,
            state_reason=base_host.state_reason,
            os_name=base_host.os_name,
            os_family=base_host.os_family,
            os_generation=base_host.os_generation,
            os_type=base_host.os_type,
            os_vendor=base_host.os_vendor,
            os_accuracy=base_host.os_accuracy
        )
        
        # Attach aggregated ports (remove duplicates by port_number+protocol)
        unique_ports = {}
        for port in all_ports:
            key = (port.port_number, port.protocol)
            if key not in unique_ports:
                unique_ports[key] = port
        
        aggregated_host.ports = list(unique_ports.values())
        aggregated_host.host_scripts = all_host_scripts
        
        aggregated_hosts.append(aggregated_host)
    
    return aggregated_hosts


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
    
    # Get subnets with host counts
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