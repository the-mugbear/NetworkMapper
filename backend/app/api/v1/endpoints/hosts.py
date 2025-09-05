from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, distinct, func
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import Host

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
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(models.Host).distinct()
    
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
    
    # Search functionality
    if search:
        query = query.filter(
            or_(
                models.Host.ip_address.contains(search),
                models.Host.hostname.contains(search),
                models.Host.os_name.contains(search),
                models.Host.os_family.contains(search)
            )
        )
    
    hosts = query.offset(skip).limit(limit).all()
    return hosts

@router.get("/{host_id}", response_model=Host)
def get_host(host_id: int, db: Session = Depends(get_db)):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    return host

@router.get("/scan/{scan_id}", response_model=List[Host])
def get_hosts_by_scan(
    scan_id: int,
    state: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(models.Host).filter(models.Host.scan_id == scan_id)
    
    if state:
        query = query.filter(models.Host.state == state)
    
    hosts = query.all()
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