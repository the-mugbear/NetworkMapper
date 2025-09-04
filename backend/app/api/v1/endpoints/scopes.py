import os
import tempfile
from typing import List
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Form
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.session import get_db
from app.db.models import Scope, Subnet, HostSubnetMapping
from app.schemas.schemas import (
    Scope as ScopeSchema, 
    ScopeSummary, 
    ScopeCreate, 
    SubnetFileUploadResponse,
    HostSubnetMapping as HostSubnetMappingSchema
)
from app.parsers.subnet_parser import SubnetParser
from app.services.subnet_correlation import SubnetCorrelationService

router = APIRouter()

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
        scope, subnets_added = parser.parse_subnet_file(
            file_content, 
            scope_name, 
            scope_description
        )
        
        return SubnetFileUploadResponse(
            message=f"Scope created successfully with {subnets_added} subnets",
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

@router.get("/{scope_id}", response_model=ScopeSchema)
def get_scope(scope_id: int, db: Session = Depends(get_db)):
    """Get a specific scope with all its subnets."""
    scope = db.query(Scope).filter(Scope.id == scope_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    
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