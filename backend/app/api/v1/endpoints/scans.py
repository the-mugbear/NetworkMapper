from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import Scan, ScanSummary, EyewitnessResult, OutOfScopeHost, DNSRecord

router = APIRouter()

@router.get("/", response_model=List[ScanSummary])
def get_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    # Get scans with summary statistics - simplified to avoid join ambiguity
    scans_query = (
        db.query(
            models.Scan.id,
            models.Scan.filename,
            models.Scan.scan_type,
            models.Scan.created_at,
            func.count(models.Host.id).label('total_hosts'),
            func.sum(case((models.Host.state == 'up', 1), else_=0)).label('up_hosts')
        )
        .select_from(models.Scan)
        .outerjoin(models.Host, models.Scan.id == models.Host.scan_id)
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
            .filter(models.Host.scan_id == result.id)
            .first()
        )
        
        scan_summaries.append(ScanSummary(
            id=result.id,
            filename=result.filename,
            scan_type=result.scan_type,
            created_at=result.created_at,
            total_hosts=result.total_hosts or 0,
            up_hosts=result.up_hosts or 0,
            total_ports=port_stats.total_ports if port_stats else 0,
            open_ports=port_stats.open_ports if port_stats else 0
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
    
    db.delete(scan)
    db.commit()
    
    return {"message": "Scan deleted successfully"}

@router.get("/{scan_id}/eyewitness", response_model=List[EyewitnessResult])
def get_scan_eyewitness_results(scan_id: int, db: Session = Depends(get_db)):
    """Get Eyewitness results for a specific scan"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    results = db.query(models.EyewitnessResult).filter(
        models.EyewitnessResult.scan_id == scan_id
    ).all()
    
    return results

@router.get("/{scan_id}/out-of-scope", response_model=List[OutOfScopeHost])
def get_scan_out_of_scope_hosts(scan_id: int, db: Session = Depends(get_db)):
    """Get out-of-scope hosts for a specific scan"""
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    hosts = db.query(models.OutOfScopeHost).filter(
        models.OutOfScopeHost.scan_id == scan_id
    ).all()
    
    return hosts

@router.get("/out-of-scope", response_model=List[OutOfScopeHost])
def get_all_out_of_scope_hosts(db: Session = Depends(get_db)):
    """Get all out-of-scope hosts across all scans"""
    hosts = db.query(models.OutOfScopeHost).all()
    return hosts