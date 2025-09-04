from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db import models
from app.schemas.schemas import DNSRecord
from app.services.dns_service import DNSService

router = APIRouter()

@router.get("/records", response_model=List[DNSRecord])
def get_dns_records(
    hostname: str = Query(..., description="Hostname to get DNS records for"),
    db: Session = Depends(get_db)
):
    """Get stored DNS records for a hostname"""
    dns_service = DNSService(db)
    records = dns_service.get_stored_dns_records(hostname)
    return records

@router.post("/lookup/{hostname}")
def perform_dns_lookup(hostname: str, db: Session = Depends(get_db)):
    """Perform DNS lookup and store results"""
    dns_service = DNSService(db)
    
    # Get various DNS records
    dns_records = dns_service.get_dns_records(hostname)
    
    return {
        "hostname": hostname,
        "records": dns_records,
        "message": f"DNS lookup completed for {hostname}"
    }

@router.post("/zone-transfer/{domain}")
def attempt_zone_transfer(domain: str, db: Session = Depends(get_db)):
    """Attempt DNS zone transfer for a domain"""
    dns_service = DNSService(db)
    
    result = dns_service.attempt_zone_transfer(domain)
    
    return result