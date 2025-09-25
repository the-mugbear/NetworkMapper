import logging
import os
import tempfile
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Form, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, aliased
from app.db import models
from app.db.session import get_db
from app.db.models import Scope, Subnet, HostSubnetMapping
from app.schemas.schemas import (
    Scope as ScopeSchema, 
    ScopeSummary, 
    ScopeCreate, 
    SubnetFileUploadResponse,
    HostSubnetMapping as HostSubnetMappingSchema,
    ScopeCoverageSummary,
    ScopeCoverageHost,
)
from app.parsers.subnet_parser import SubnetParser
from app.services.subnet_correlation import SubnetCorrelationService

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/upload-subnets", response_model=SubnetFileUploadResponse)
async def upload_subnet_file(
    scope_name: str = Form(...),
    scope_description: str = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload a subnet file and create a new scope."""
    
    # Validate file type (accept .txt, .csv files)
    allowed_extensions = ['.txt', '.csv']
    if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"File type not allowed. Supported types: {', '.join(allowed_extensions)}"
        )
    
    # Check if scope name already exists
    existing_scope = db.query(Scope).filter(Scope.name == scope_name).first()
    if existing_scope:
        raise HTTPException(
            status_code=400,
            detail=f"Scope with name '{scope_name}' already exists"
        )
    
    # Read file content
    content = await file.read()
    try:
        file_content = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File must be UTF-8 encoded text"
        )
    
    try:
        # Parse subnets
        parser = SubnetParser(db)
        correlation_service = SubnetCorrelationService(db)

        scope, subnets_added = parser.parse_subnet_file(
            file_content,
            scope_name,
            scope_description
        )

        # Ensure future lookups see the new subnets
        correlation_service.invalidate_subnet_cache()

        correlated_hosts = None
        try:
            correlated_hosts = correlation_service.correlate_all_hosts_to_subnets()
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Subnet correlation after upload failed: %s", exc)

        message = f"Scope created successfully with {subnets_added} subnets"
        if correlated_hosts is not None:
            message += f"; correlated {correlated_hosts} host-subnet relationships"

        return SubnetFileUploadResponse(
            message=message,
            scope_id=scope.id,
            subnets_added=subnets_added,
            filename=file.filename
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

@router.get("/", response_model=List[ScopeSummary])
def get_scopes(db: Session = Depends(get_db)):
    """Get all scopes with summary information."""
    scopes = db.query(
        Scope.id,
        Scope.name,
        Scope.description,
        Scope.created_at,
        func.count(Subnet.id).label('subnet_count')
    ).outerjoin(Subnet).group_by(Scope.id).all()
    
    return [
        ScopeSummary(
            id=scope.id,
            name=scope.name,
            description=scope.description,
            created_at=scope.created_at,
            subnet_count=scope.subnet_count
        )
        for scope in scopes
    ]


@router.get("/coverage", response_model=ScopeCoverageSummary)
def get_scope_coverage(
    limit: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Return aggregate coverage information and recent out-of-scope hosts."""

    total_scopes = db.query(func.count(Scope.id)).scalar() or 0
    total_subnets = db.query(func.count(Subnet.id)).scalar() or 0
    total_hosts = db.query(func.count(models.Host.id)).scalar() or 0
    scoped_hosts = (
        db.query(func.count(func.distinct(HostSubnetMapping.host_id))).scalar() or 0
    )

    out_of_scope_count = max(total_hosts - scoped_hosts, 0)
    coverage_percentage = (
        (scoped_hosts / total_hosts) * 100 if total_hosts > 0 else 0.0
    )

    scan_alias = aliased(models.Scan)

    recent_out_of_scope = (
        db.query(
            models.Host.id.label("host_id"),
            models.Host.ip_address,
            models.Host.hostname,
            models.Host.last_seen,
            models.Host.last_updated_scan_id,
            scan_alias.filename.label("scan_filename"),
        )
        .outerjoin(HostSubnetMapping, HostSubnetMapping.host_id == models.Host.id)
        .outerjoin(scan_alias, scan_alias.id == models.Host.last_updated_scan_id)
        .filter(HostSubnetMapping.host_id.is_(None))
        .order_by(models.Host.last_seen.desc().nullslast())
        .limit(limit)
        .all()
    )

    recent_entries = [
        ScopeCoverageHost(
            host_id=row.host_id,
            ip_address=row.ip_address,
            hostname=row.hostname,
            last_seen=row.last_seen,
            last_scan_id=row.last_updated_scan_id,
            last_scan_filename=row.scan_filename,
        )
        for row in recent_out_of_scope
    ]

    return ScopeCoverageSummary(
        total_scopes=total_scopes,
        total_subnets=total_subnets,
        total_hosts=total_hosts,
        scoped_hosts=scoped_hosts,
        out_of_scope_hosts=out_of_scope_count,
        coverage_percentage=coverage_percentage,
        has_scope_configuration=total_subnets > 0,
        recent_out_of_scope_hosts=recent_entries,
    )


@router.get("/{scope_id}", response_model=ScopeSchema)
def get_scope(
    scope_id: int, 
    with_findings_only: Optional[bool] = Query(True, description="Only show subnets with correlated host findings"),
    db: Session = Depends(get_db)
):
    """Get a specific scope with its subnets, optionally filtered by findings."""
    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    
    # If filtering by findings, modify the subnets to only include those with host mappings
    if with_findings_only:
        # Get subnets that have at least one host mapping
        scope_dict = {
            "id": scope.id,
            "name": scope.name,
            "description": scope.description,
            "created_at": scope.created_at,
            "updated_at": scope.updated_at,
            "subnets": []
        }
        
        # Query subnets with host counts
        subnets_with_hosts = db.query(
            Subnet,
            func.count(HostSubnetMapping.id).label('host_count')
        ).outerjoin(HostSubnetMapping).filter(
            Subnet.scope_id == scope_id
        ).group_by(Subnet.id).having(
            func.count(HostSubnetMapping.id) > 0
        ).all()
        
        scope_dict["subnets"] = [subnet for subnet, _ in subnets_with_hosts]
        return scope_dict
    
    return scope

@router.post("/", response_model=ScopeSchema)
def create_scope(scope: ScopeCreate, db: Session = Depends(get_db)):
    """Create a new empty scope."""
    # Check if scope name already exists
    existing_scope = db.query(Scope).filter(Scope.name == scope.name).first()
    if existing_scope:
        raise HTTPException(
            status_code=400,
            detail=f"Scope with name '{scope.name}' already exists"
        )
    
    db_scope = Scope(**scope.dict())
    db.add(db_scope)
    db.commit()
    db.refresh(db_scope)
    
    return db_scope

@router.delete("/{scope_id}")
def delete_scope(scope_id: int, db: Session = Depends(get_db)):
    """Delete a scope and all its subnets."""
    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    
    db.delete(scope)
    db.commit()
    
    return {"message": "Scope deleted successfully"}

@router.get("/{scope_id}/host-mappings", response_model=List[HostSubnetMappingSchema])
def get_scope_host_mappings(scope_id: int, db: Session = Depends(get_db)):
    """Get all host-subnet mappings for a specific scope."""
    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    
    mappings = db.query(HostSubnetMapping).join(Subnet).filter(
        Subnet.scope_id == scope_id
    ).all()
    
    return mappings

@router.post("/correlate-all")
def correlate_all_hosts(db: Session = Depends(get_db)):
    """Manually correlate all existing hosts to subnets."""
    correlation_service = SubnetCorrelationService(db)
    mappings_created = correlation_service.correlate_all_hosts_to_subnets()
    
    return {
        "message": f"Successfully created {mappings_created} host-subnet mappings",
        "mappings_created": mappings_created
    }
