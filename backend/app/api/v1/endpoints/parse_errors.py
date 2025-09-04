from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.db.session import get_db
from app.db import models
from app.schemas.schemas import ParseError, ParseErrorSummary, ParseErrorCreate

router = APIRouter()

@router.get("/", response_model=List[ParseErrorSummary])
def get_parse_errors(
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    db: Session = Depends(get_db)
):
    """Get list of parsing errors with optional status filter"""
    query = db.query(models.ParseError)
    
    if status:
        query = query.filter(models.ParseError.status == status)
    
    errors = query.order_by(desc(models.ParseError.created_at)).offset(skip).limit(limit).all()
    return errors

@router.get("/{error_id}", response_model=ParseError)
def get_parse_error(error_id: int, db: Session = Depends(get_db)):
    """Get detailed parse error by ID"""
    error = db.query(models.ParseError).filter(models.ParseError.id == error_id).first()
    if not error:
        raise HTTPException(status_code=404, detail="Parse error not found")
    return error

@router.put("/{error_id}/status")
def update_parse_error_status(
    error_id: int,
    status: str,
    db: Session = Depends(get_db)
):
    """Update parse error status (reviewed, fixed, ignored)"""
    valid_statuses = ["unresolved", "reviewed", "fixed", "ignored"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )
    
    error = db.query(models.ParseError).filter(models.ParseError.id == error_id).first()
    if not error:
        raise HTTPException(status_code=404, detail="Parse error not found")
    
    error.status = status
    db.commit()
    db.refresh(error)
    
    return {"message": f"Parse error status updated to {status}"}

@router.delete("/{error_id}")
def delete_parse_error(error_id: int, db: Session = Depends(get_db)):
    """Delete a parse error record"""
    error = db.query(models.ParseError).filter(models.ParseError.id == error_id).first()
    if not error:
        raise HTTPException(status_code=404, detail="Parse error not found")
    
    db.delete(error)
    db.commit()
    
    return {"message": "Parse error deleted successfully"}

@router.get("/stats/summary")
def get_parse_error_stats(db: Session = Depends(get_db)):
    """Get parse error statistics"""
    total_errors = db.query(models.ParseError).count()
    unresolved_errors = db.query(models.ParseError).filter(models.ParseError.status == "unresolved").count()
    reviewed_errors = db.query(models.ParseError).filter(models.ParseError.status == "reviewed").count()
    fixed_errors = db.query(models.ParseError).filter(models.ParseError.status == "fixed").count()
    ignored_errors = db.query(models.ParseError).filter(models.ParseError.status == "ignored").count()
    
    return {
        "total_errors": total_errors,
        "unresolved": unresolved_errors,
        "reviewed": reviewed_errors,
        "fixed": fixed_errors,
        "ignored": ignored_errors
    }