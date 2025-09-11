from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import Scan, ScanSummary, EyewitnessResult, OutOfScopeHost, DNSRecord
from app.services.command_explanation_service import CommandExplanationService

router = APIRouter()

@router.get("/", response_model=List[ScanSummary])
def get_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    # Get scans with summary statistics using v2 audit tables
    scans_query = (
        db.query(
            models.Scan.id,
            models.Scan.filename,
            models.Scan.scan_type,
            models.Scan.created_at,
            func.count(models.HostScanHistory.id).label('total_hosts'),
            func.sum(case((models.Host.state == 'up', 1), else_=0)).label('up_hosts')
        )
        .select_from(models.Scan)
        .outerjoin(models.HostScanHistory, models.Scan.id == models.HostScanHistory.scan_id)
        .outerjoin(models.Host, models.HostScanHistory.host_id == models.Host.id)
        .group_by(models.Scan.id, models.Scan.filename, models.Scan.scan_type, models.Scan.created_at)
        .order_by(desc(models.Scan.created_at))
        .offset(skip)
        .limit(limit)
    )
    
    results = scans_query.all()
    
    # Calculate port stats separately for each scan to avoid join complexity
    scan_summaries = []
    for result in results:
        # Get port statistics for this specific scan
        port_stats = (
            db.query(
                func.count(models.Port.id).label('total_ports'),
                func.sum(case((models.Port.state == 'open', 1), else_=0)).label('open_ports')
            )
            .select_from(models.Port)
            .join(models.Host, models.Port.host_id == models.Host.id)
            .join(models.HostScanHistory, models.Host.id == models.HostScanHistory.host_id)
            .filter(models.HostScanHistory.scan_id == result.id)
            .first()
        )
        
        scan_summaries.append(ScanSummary(
            id=result.id,
            filename=result.filename,
            scan_type=result.scan_type,
            created_at=result.created_at,
            total_hosts=result.total_hosts or 0,
            up_hosts=result.up_hosts or 0,
            total_ports=port_stats.total_ports if port_stats and port_stats.total_ports else 0,
            open_ports=port_stats.open_ports if port_stats and port_stats.open_ports else 0
        ))
    
    return scan_summaries

@router.get("/{scan_id}", response_model=Scan)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.delete("/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        # Handle cascading deletions properly for v2 schema
        # Use step-by-step deletion with intermediate commits to handle foreign key constraints
        from sqlalchemy import text
        
        # Step 1: Delete scripts_v2 entries that reference ports from this scan
        scripts_deleted = db.execute(text("""
            DELETE FROM scripts_v2 
            WHERE scan_id = :scan_id
        """), {"scan_id": scan_id})
        db.commit()
        
        # Step 2: Delete host_scripts_v2 entries from this scan
        host_scripts_deleted = db.query(models.HostScript).filter(models.HostScript.scan_id == scan_id).delete()
        db.commit()
        
        # Step 3: Delete eyewitness_results from this scan
        eyewitness_deleted = db.query(models.EyewitnessResult).filter(models.EyewitnessResult.scan_id == scan_id).delete()
        db.commit()
        
        # Step 4: Delete out_of_scope_hosts from this scan  
        out_of_scope_deleted = db.query(models.OutOfScopeHost).filter(models.OutOfScopeHost.scan_id == scan_id).delete()
        db.commit()
        
        # Step 5: Delete scan_info entries
        scan_info_deleted = db.query(models.ScanInfo).filter(models.ScanInfo.scan_id == scan_id).delete()
        db.commit()
        
        # Step 6: Update hosts that have this scan as their last_updated_scan_id
        hosts_to_update = db.query(models.Host).filter(models.Host.last_updated_scan_id == scan_id).all()
        for host in hosts_to_update:
            # Find the most recent previous scan for this host
            previous_scan_history = db.query(models.HostScanHistory).filter(
                models.HostScanHistory.host_id == host.id,
                models.HostScanHistory.scan_id != scan_id
            ).order_by(models.HostScanHistory.discovered_at.desc()).first()
            
            if previous_scan_history:
                host.last_updated_scan_id = previous_scan_history.scan_id
            else:
                host.last_updated_scan_id = None
        db.commit()
        
        # Step 7: Update ports that have this scan as their last_updated_scan_id
        ports_to_update = db.query(models.Port).filter(models.Port.last_updated_scan_id == scan_id).all()
        for port in ports_to_update:
            # For ports, find the most recent scan that saw this port (excluding current scan)
            port_history = db.query(models.PortScanHistory).filter(
                models.PortScanHistory.port_id == port.id,
                models.PortScanHistory.scan_id != scan_id
            ).order_by(models.PortScanHistory.discovered_at.desc()).first()
            
            if port_history:
                port.last_updated_scan_id = port_history.scan_id
            else:
                port.last_updated_scan_id = None
        db.commit()
        
        # Step 8: Delete port_scan_history entries (after updating port references)
        port_scan_count = db.query(models.PortScanHistory).filter(models.PortScanHistory.scan_id == scan_id).count()
        db.query(models.PortScanHistory).filter(models.PortScanHistory.scan_id == scan_id).delete()
        db.commit()
        print(f"Deleted {port_scan_count} port_scan_history records for scan {scan_id}")
        
        # Step 9: Delete host_scan_history entries (after updating all references)
        host_scan_count = db.query(models.HostScanHistory).filter(models.HostScanHistory.scan_id == scan_id).delete()
        db.commit()
        
        # Step 10: Finally delete the scan itself
        db.delete(scan)
        db.commit()
        
        return {"message": "Scan deleted successfully"}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting scan: {str(e)}")

@router.get("/{scan_id}/eyewitness", response_model=List[EyewitnessResult])
def get_scan_eyewitness_results(
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get Eyewitness results for a specific scan with pagination"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    results = db.query(models.EyewitnessResult).filter(
        models.EyewitnessResult.scan_id == scan_id
    ).order_by(models.EyewitnessResult.ip_address, models.EyewitnessResult.port)\
     .offset(skip).limit(limit).all()
    
    return results

@router.get("/{scan_id}/out-of-scope", response_model=List[OutOfScopeHost])
def get_scan_out_of_scope_hosts(
    scan_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get out-of-scope hosts for a specific scan with pagination"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    hosts = db.query(models.OutOfScopeHost).filter(
        models.OutOfScopeHost.scan_id == scan_id
    ).order_by(models.OutOfScopeHost.ip_address)\
     .offset(skip).limit(limit).all()
    
    return hosts

@router.get("/out-of-scope", response_model=List[OutOfScopeHost])
def get_all_out_of_scope_hosts(db: Session = Depends(get_db)):
    """Get all out-of-scope hosts across all scans"""
    hosts = db.query(models.OutOfScopeHost).all()
    return hosts

@router.get("/{scan_id}/command-explanation", response_model=Dict[str, Any])
def get_scan_command_explanation(scan_id: int, db: Session = Depends(get_db)):
    """Get detailed explanation of the scan command and its arguments"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # If no command line available, return basic info
    if not scan.command_line:
        return {
            "has_command": False,
            "tool": scan.tool_name or "Unknown",
            "message": "No command line information available for this scan"
        }
    
    # Analyze the command
    explanation_service = CommandExplanationService()
    analysis = explanation_service.analyze_command(scan.command_line, scan.tool_name)
    
    if not analysis:
        return {
            "has_command": True,
            "tool": scan.tool_name or "Unknown",
            "command": scan.command_line,
            "message": "Unable to parse command line arguments"
        }
    
    # Convert the analysis to a dictionary format for JSON response
    return {
        "has_command": True,
        "tool": analysis.tool,
        "command": analysis.command,
        "target": analysis.target,
        "scan_type": analysis.scan_type,
        "summary": analysis.summary,
        "risk_assessment": analysis.risk_assessment,
        "arguments": [
            {
                "arg": arg.arg,
                "description": arg.description,
                "category": arg.category,
                "risk_level": arg.risk_level,
                "examples": arg.examples
            }
            for arg in analysis.arguments
        ]
    }

@router.get("/{scan_id}/hosts/count")
def get_scan_hosts_count(scan_id: int, state: Optional[str] = None, db: Session = Depends(get_db)):
    """Get total count of hosts for a scan (for pagination)"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    query = db.query(models.Host).join(models.HostScanHistory, models.Host.id == models.HostScanHistory.host_id).filter(models.HostScanHistory.scan_id == scan_id)
    if state:
        query = query.filter(models.Host.state == state)
    
    count = query.count()
    return {"total": count}

@router.get("/{scan_id}/eyewitness/count")
def get_scan_eyewitness_count(scan_id: int, db: Session = Depends(get_db)):
    """Get total count of Eyewitness results for a scan (for pagination)"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    count = db.query(models.EyewitnessResult).filter(
        models.EyewitnessResult.scan_id == scan_id
    ).count()
    return {"total": count}

@router.get("/{scan_id}/out-of-scope/count")
def get_scan_out_of_scope_count(scan_id: int, db: Session = Depends(get_db)):
    """Get total count of out-of-scope hosts for a scan (for pagination)"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    count = db.query(models.OutOfScopeHost).filter(
        models.OutOfScopeHost.scan_id == scan_id
    ).count()
    return {"total": count}