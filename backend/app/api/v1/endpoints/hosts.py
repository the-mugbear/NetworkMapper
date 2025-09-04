from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import Host

router = APIRouter()

@router.get("/", response_model=List[Host])
def get_hosts(
    scan_id: Optional[int] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(models.Host)
    
    # Filter by scan_id if provided
    if scan_id:
        query = query.filter(models.Host.scan_id == scan_id)
    
    # Filter by state if provided
    if state:
        query = query.filter(models.Host.state == state)
    
    # Search functionality
    if search:
        query = query.filter(
            or_(
                models.Host.ip_address.contains(search),
                models.Host.hostname.contains(search),
                models.Host.os_name.contains(search)
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