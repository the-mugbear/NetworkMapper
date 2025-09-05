from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import DashboardStats, ScanSummary, SubnetStats
from app.services.subnet_calculator import SubnetCalculator

router = APIRouter()

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    # Get total counts
    total_scans = db.query(func.count(models.Scan.id)).scalar() or 0
    total_hosts = db.query(func.count(models.Host.id)).scalar() or 0
    total_ports = db.query(func.count(models.Port.id)).scalar() or 0
    total_subnets = db.query(func.count(models.Subnet.id)).scalar() or 0
    
    # Get recent scans (last 10) - simplified query without joins
    recent_scans_query = (
        db.query(models.Scan)
        .order_by(desc(models.Scan.created_at))
        .limit(10)
    )
    
    recent_results = recent_scans_query.all()
    
    recent_scans = [
        ScanSummary(
            id=result.id,
            filename=result.filename,
            scan_type=result.scan_type,
            created_at=result.created_at,
            total_hosts=0,
            up_hosts=0,
            total_ports=0,
            open_ports=0
        )
        for result in recent_results
    ]
    
    # Get enhanced subnet statistics with calculations
    subnet_stats = []
    
    try:
        # Get basic subnet info with scope names
        subnets = db.query(models.Subnet).join(models.Scope).limit(20).all()
        
        for subnet in subnets:
            # Count mappings for each subnet individually
            host_count = db.query(func.count(models.HostSubnetMapping.id)).filter(
                models.HostSubnetMapping.subnet_id == subnet.id
            ).scalar() or 0
            
            # Calculate subnet metrics using the new calculator
            metrics = SubnetCalculator.calculate_subnet_metrics(subnet.cidr)
            utilization = SubnetCalculator.calculate_utilization_percentage(host_count, subnet.cidr)
            risk_info = SubnetCalculator.get_subnet_risk_level(utilization, host_count)
            
            subnet_stats.append(SubnetStats(
                id=subnet.id,
                cidr=subnet.cidr,
                scope_name=subnet.scope.name,
                description=subnet.description,
                host_count=host_count,
                total_addresses=metrics['total_addresses'],
                usable_addresses=metrics['usable_addresses'],
                utilization_percentage=round(utilization, 2),
                risk_level=risk_info['risk_level'],
                network_address=metrics['network_address'],
                is_private=metrics['is_private']
            ))
            
        # Sort by utilization percentage descending, then by host count
        subnet_stats.sort(key=lambda x: (x.utilization_percentage, x.host_count), reverse=True)
        
    except Exception as e:
        print(f"Subnet stats error: {e}")
        subnet_stats = []
    
    return DashboardStats(
        total_scans=total_scans,
        total_hosts=total_hosts,
        total_ports=total_ports,
        total_subnets=total_subnets,
        recent_scans=recent_scans,
        subnet_stats=subnet_stats
    )

@router.get("/port-stats")
def get_port_statistics(db: Session = Depends(get_db)):
    # Get top 20 most common open ports
    port_stats = (
        db.query(
            models.Port.port_number,
            models.Port.service_name,
            func.count(models.Port.id).label('count')
        )
        .filter(models.Port.state == 'open')
        .group_by(models.Port.port_number, models.Port.service_name)
        .order_by(desc(func.count(models.Port.id)))
        .limit(20)
        .all()
    )
    
    return [
        {
            "port": stat.port_number,
            "service": stat.service_name or "unknown",
            "count": stat.count
        }
        for stat in port_stats
    ]

@router.get("/os-stats")
def get_os_statistics(db: Session = Depends(get_db)):
    # Get operating system distribution
    os_stats = (
        db.query(
            models.Host.os_name,
            func.count(models.Host.id).label('count')
        )
        .filter(models.Host.os_name.isnot(None))
        .group_by(models.Host.os_name)
        .order_by(desc(func.count(models.Host.id)))
        .limit(10)
        .all()
    )
    
    return [
        {
            "os": stat.os_name,
            "count": stat.count
        }
        for stat in os_stats
    ]