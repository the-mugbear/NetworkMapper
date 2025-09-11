import os
import tempfile
import time
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings
from app.parsers.nmap_parser import NmapXMLParser
from app.parsers.eyewitness_parser import EyewitnessParser
from app.parsers.masscan_parser import MasscanParser
from app.parsers.dns_parser import DNSParser
from app.schemas.schemas import FileUploadResponse
from app.services.dns_service import DNSService
from app.services.parse_error_service import log_parse_error

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/", response_model=FileUploadResponse)
async def upload_scan_file(
    file: UploadFile = File(...),
    enrich_dns: bool = False,
    dns_server: str = None,
    db: Session = Depends(get_db)
):
    # Extended allowed extensions for multiple tools
    allowed_extensions = ['.xml', '.json', '.csv', '.txt', '.gnmap']
    
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
            
        elif file.filename.lower().endswith('.gnmap'):
            # Lazy import to avoid dependency issues at module load time
            try:
                from app.parsers.gnmap_parser import GnmapParser
                parsing_attempts.append(("nmap_gnmap", GnmapParser, "Nmap .gnmap file"))
            except ImportError as e:
                logger.warning(f"GnmapParser not available: {str(e)}")
                parse_error = log_parse_error(
                    db=db,
                    filename=file.filename,
                    file_content=content,
                    error_type="import_error",
                    file_type="nmap_gnmap",
                    custom_message=f"GnmapParser dependencies not available: {str(e)}"
                )
                raise HTTPException(
                    status_code=500,
                    detail=f"Gnmap parser not available. Error ID: {parse_error.id}"
                )
        
        elif file.filename.lower().endswith('.csv') and ('dns' in file.filename.lower() or 'ptr' in file.filename.lower()):
            # DNS records CSV file
            parsing_attempts.append(("dns_csv", DNSParser, "DNS records CSV file"))
        
        elif file.filename.lower().endswith('.csv'):
            # Generic CSV - try DNS parser as fallback for CSV files
            parsing_attempts.append(("dns_csv", DNSParser, "DNS records CSV file"))
        
        else:
            # Log unsupported file type error
            parse_error = log_parse_error(
                db=db,
                filename=file.filename,
                file_content=content,
                error_type="format_error",
                file_type="unknown",
                custom_message=f"Unsupported file type or format. Supported formats: Nmap XML/.gnmap, Masscan XML/JSON/List, Eyewitness JSON/CSV, DNS Records CSV"
            )
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file format. Error ID: {parse_error.id} - Check parse errors for details."
            )
        
        # Try each parser until one succeeds
        last_error = None
        for file_type, parser_class, success_message in parsing_attempts:
            try:
                logger.info(f"Attempting to parse {file.filename} with {parser_class.__name__}")
                parse_start_time = time.time()
                
                parser = parser_class(db)
                scan = parser.parse_file(temp_file_path, file.filename)
                
                # IMMEDIATE COMMIT - CRITICAL FIX FOR SCAN PERSISTENCE
                db.commit()
                logger.error(f"CRITICAL: Committed scan {scan.id} to database - this should appear in logs!")
                
                logger.info(f"About to commit scan {scan.id} to database")
                # Commit immediately after parsing to ensure persistence
                db.commit()
                logger.info(f"Committed scan {scan.id} to database after parsing")
                
                parse_elapsed = time.time() - parse_start_time
                logger.info(f"Successfully parsed {file.filename} with {parser_class.__name__} in {parse_elapsed:.2f} seconds")
                
                message = f"{success_message} uploaded and parsed successfully (parsed in {parse_elapsed:.2f}s)"
                break
            except Exception as e:
                parse_elapsed = time.time() - parse_start_time
                logger.warning(f"Failed to parse {file.filename} with {parser_class.__name__} after {parse_elapsed:.2f} seconds: {str(e)}")
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
        
        logger.info(f"Parsing completed successfully, scan ID: {scan.id}")
        
        # TODO: Re-enable DNS enrichment after fixing scan.hosts relationship
        # # Enrich with DNS data if requested
        # if enrich_dns and scan:
        #     try:
        #         dns_service = DNSService(db, custom_dns_server=dns_server if dns_server else None)
        #         enriched_count = 0
        #         
        #         # Get hosts associated with this scan from the database
        #         from app.db import models
        #         from sqlalchemy.orm import Session
        #         scan_hosts = db.query(models.Host).join(models.HostScanHistory).filter(
        #             models.HostScanHistory.scan_id == scan.id
        #         ).all()
        #         
        #         logger.info(f"Starting DNS enrichment for scan {scan.id} with {len(scan_hosts)} hosts"
        #                    f" using {'custom DNS server: ' + dns_server if dns_server else 'system default DNS'}")
        #         
        #         for host in scan_hosts:
        #             try:
        #                 enrichment_data = dns_service.enrich_host_data(host)
        #                 if enrichment_data['reverse_dns'] or enrichment_data['dns_records']:
        #                     enriched_count += 1
        #             except Exception as e:
        #                 # Log but don't fail the entire upload
        #                 logger.warning(f"DNS enrichment failed for host {host.ip_address}: {str(e)}")
        #         
        #         if enriched_count > 0:
        #             message += f" (DNS enriched {enriched_count} hosts using {'custom server: ' + dns_server if dns_server else 'system DNS'})"
        #     except Exception as e:
        #         logger.error(f"DNS enrichment failed for scan {scan.id}: {str(e)}")
        #         # Continue without DNS enrichment
        
        # Commit the transaction to persist all changes
        logger.info(f"Committing scan {scan.id} to database")
        db.commit()
        logger.info(f"Successfully committed scan {scan.id}")
        
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