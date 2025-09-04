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
from app.services.parse_error_service import log_parse_error

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
        scan = None
        message = ""
        parsing_attempts = []
        
        # Try different parsers based on file type and name
        if file.filename.lower().endswith('.xml'):
            # Try Nmap parser first
            parsing_attempts.append(("nmap_xml", NmapXMLParser, "Nmap XML file"))
            # Then try Masscan XML parser
            parsing_attempts.append(("masscan_xml", MasscanParser, "Masscan XML file"))
            
        elif (file.filename.lower().endswith('.json') or file.filename.lower().endswith('.csv')) and \
             ('eyewitness' in file.filename.lower() or 'report' in file.filename.lower()):
            file_type = "eyewitness_json" if file.filename.lower().endswith('.json') else "eyewitness_csv"
            parsing_attempts.append((file_type, EyewitnessParser, "Eyewitness report"))
            
        elif file.filename.lower().endswith('.json') and 'masscan' in file.filename.lower():
            parsing_attempts.append(("masscan_json", MasscanParser, "Masscan JSON file"))
            
        elif file.filename.lower().endswith('.txt'):
            parsing_attempts.append(("masscan_list", MasscanParser, "Masscan output file"))
        
        else:
            # Log unsupported file type error
            parse_error = log_parse_error(
                db=db,
                filename=file.filename,
                file_content=content,
                error_type="format_error",
                file_type="unknown",
                custom_message=f"Unsupported file type or format. Supported formats: Nmap XML, Masscan XML/JSON/List, Eyewitness JSON/CSV"
            )
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file format. Error ID: {parse_error.id} - Check parse errors for details."
            )
        
        # Try each parser until one succeeds
        last_error = None
        for file_type, parser_class, success_message in parsing_attempts:
            try:
                parser = parser_class(db)
                scan = parser.parse_file(temp_file_path, file.filename)
                message = f"{success_message} uploaded and parsed successfully"
                break
            except Exception as e:
                last_error = e
                continue
        
        # If all parsers failed, log the error
        if not scan:
            parse_error = log_parse_error(
                db=db,
                filename=file.filename,
                file_content=content,
                error=last_error,
                error_type="parsing_error",
                file_type=parsing_attempts[0][0] if parsing_attempts else "unknown"
            )
            
            raise HTTPException(
                status_code=400,
                detail=f"Failed to parse file. Error ID: {parse_error.id} - Check parse errors for detailed information and suggestions."
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