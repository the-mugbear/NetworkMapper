import os
import tempfile
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings
from app.parsers.nmap_parser import NmapXMLParser
from app.parsers.eyewitness_parser import EyewitnessParser
from app.parsers.masscan_parser import MasscanParser
from app.schemas.schemas import FileUploadResponse
from app.services.dns_service import DNSService

router = APIRouter()

@router.post("/", response_model=FileUploadResponse)
async def upload_scan_file(
    file: UploadFile = File(...),
    enrich_dns: bool = False,
    db: Session = Depends(get_db)
):
    # Extended allowed extensions for multiple tools
    allowed_extensions = ['.xml', '.json', '.csv', '.txt']
    
    if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail=f"File type not allowed. Supported types: {', '.join(allowed_extensions)}"
        )
    
    # Validate file size
    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE // (1024*1024)}MB"
        )
    
    # Create uploads directory if it doesn't exist
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    
    # Save file temporarily for parsing
    file_extension = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as temp_file:
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    try:
        # Determine parser based on file content and name
        parser = None
        scan = None
        
        # Check if it's an Nmap XML file
        if file.filename.lower().endswith('.xml'):
            try:
                # Try Nmap parser first
                parser = NmapXMLParser(db)
                scan = parser.parse_file(temp_file_path, file.filename)
                message = "Nmap XML file uploaded and parsed successfully"
            except Exception:
                try:
                    # Try Masscan XML parser
                    parser = MasscanParser(db)
                    scan = parser.parse_file(temp_file_path, file.filename)
                    message = "Masscan XML file uploaded and parsed successfully"
                except Exception as e:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Error parsing XML file: {str(e)}"
                    )
        
        # Check for Eyewitness files
        elif (file.filename.lower().endswith('.json') or file.filename.lower().endswith('.csv')) and \
             ('eyewitness' in file.filename.lower() or 'report' in file.filename.lower()):
            parser = EyewitnessParser(db)
            scan = parser.parse_file(temp_file_path, file.filename)
            message = "Eyewitness report uploaded and parsed successfully"
        
        # Check for Masscan output files
        elif file.filename.lower().endswith('.json') and 'masscan' in file.filename.lower():
            parser = MasscanParser(db)
            scan = parser.parse_file(temp_file_path, file.filename)
            message = "Masscan JSON file uploaded and parsed successfully"
        
        # Default to trying Masscan list format for .txt files
        elif file.filename.lower().endswith('.txt'):
            parser = MasscanParser(db)
            scan = parser.parse_file(temp_file_path, file.filename)
            message = "Masscan output file uploaded and parsed successfully"
        
        else:
            raise HTTPException(
                status_code=400,
                detail="Unable to determine file type. Please ensure filename contains tool identifier (nmap, masscan, eyewitness)"
            )
        
        # Enrich with DNS data if requested
        if enrich_dns and scan:
            dns_service = DNSService(db)
            enriched_count = 0
            
            for host in scan.hosts:
                try:
                    enrichment_data = dns_service.enrich_host_data(host)
                    if enrichment_data['reverse_dns'] or enrichment_data['dns_records']:
                        enriched_count += 1
                except Exception as e:
                    # Log but don't fail the entire upload
                    print(f"DNS enrichment failed for host {host.ip_address}: {str(e)}")
            
            if enriched_count > 0:
                message += f" (DNS enriched {enriched_count} hosts)"
        
        return FileUploadResponse(
            message=message,
            scan_id=scan.id,
            filename=file.filename
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error processing file: {str(e)}"
        )
    
    finally:
        # Clean up temporary file
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)