import json
import csv
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session
from app.db import models
from app.services.subnet_correlation import SubnetCorrelationService
import logging
import time

logger = logging.getLogger(__name__)

class EyewitnessParser:
    def __init__(self, db: Session):
        self.db = db
        self.correlation_service = SubnetCorrelationService(db)

    def parse_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Eyewitness report files (JSON or CSV format)"""
        start_time = time.time()
        logger.info(f"Starting Eyewitness parse of {filename}")
        
        try:
            if filename.lower().endswith('.json'):
                result = self._parse_json_file(file_path, filename)
            elif filename.lower().endswith('.csv'):
                result = self._parse_csv_file(file_path, filename)
            else:
                raise ValueError("Unsupported Eyewitness file format. Expected .json or .csv")
            
            elapsed_time = time.time() - start_time
            logger.info(f"Successfully parsed Eyewitness {filename} in {elapsed_time:.2f} seconds")
            return result
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Error parsing Eyewitness file {filename} after {elapsed_time:.2f} seconds: {str(e)}")
            raise

    def _parse_json_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Eyewitness JSON report"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Create scan record
        scan = models.Scan(
            filename=filename,
            scan_type='web_screenshot',
            tool_name='eyewitness',
            version=data.get('version'),
            created_at=datetime.utcnow()
        )
        
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        
        # Parse results
        results = data.get('results', [])
        out_of_scope_count = 0
        logger.info(f"Processing {len(results)} Eyewitness results")
        
        for i, result_data in enumerate(results, 1):
            if i % 100 == 0 or i == 1:  # Log progress every 100 results
                logger.info(f"Processing Eyewitness result {i}/{len(results)} ({i/len(results)*100:.1f}%)")
            try:
                # Extract IP address from URL
                ip_address = self._extract_ip_from_url(result_data.get('url', ''))
                
                # Create Eyewitness result
                result = models.EyewitnessResult(
                    scan_id=scan.id,
                    url=result_data.get('url'),
                    protocol=result_data.get('protocol'),
                    port=result_data.get('port'),
                    ip_address=ip_address,
                    title=result_data.get('title'),
                    server_header=result_data.get('server'),
                    content_length=result_data.get('content_length'),
                    screenshot_path=result_data.get('screenshot_path'),
                    response_code=result_data.get('response_code'),
                    page_text=result_data.get('page_text')
                )
                
                self.db.add(result)
                
                # Check if IP is in scope
                if ip_address:
                    matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
                    if not matching_subnets:
                        # Create out-of-scope entry
                        out_of_scope = models.OutOfScopeHost(
                            scan_id=scan.id,
                            ip_address=ip_address,
                            hostname=self._extract_hostname_from_url(result_data.get('url', '')),
                            ports={'web': result_data.get('port', 80)},
                            tool_source='eyewitness',
                            reason='IP address not found in any defined subnet scope'
                        )
                        self.db.add(out_of_scope)
                        out_of_scope_count += 1
                
            except Exception as e:
                logger.warning(f"Error processing Eyewitness result {result_data}: {str(e)}")
                continue
        
        self.db.commit()
        
        logger.info(f"Processed {len(results)} Eyewitness results, {out_of_scope_count} out of scope")
        return scan

    def _parse_csv_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Eyewitness CSV report"""
        # Create scan record
        scan = models.Scan(
            filename=filename,
            scan_type='web_screenshot',
            tool_name='eyewitness',
            created_at=datetime.utcnow()
        )
        
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        
        out_of_scope_count = 0
        
        with open(file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)  # Load all rows to count them
            logger.info(f"Processing {len(rows)} Eyewitness CSV rows")
            
            for i, row in enumerate(rows, 1):
                if i % 100 == 0 or i == 1:  # Log progress every 100 rows
                    logger.info(f"Processing CSV row {i}/{len(rows)} ({i/len(rows)*100:.1f}%)")
                try:
                    # Extract IP address from URL
                    url = row.get('URL', row.get('url', ''))
                    ip_address = self._extract_ip_from_url(url)
                    
                    # Create Eyewitness result
                    result = models.EyewitnessResult(
                        scan_id=scan.id,
                        url=url,
                        protocol=row.get('Protocol', row.get('protocol')),
                        port=self._safe_int(row.get('Port', row.get('port'))),
                        ip_address=ip_address,
                        title=row.get('Title', row.get('title')),
                        server_header=row.get('Server', row.get('server')),
                        content_length=self._safe_int(row.get('Content Length', row.get('content_length'))),
                        screenshot_path=row.get('Screenshot Path', row.get('screenshot_path')),
                        response_code=self._safe_int(row.get('Response Code', row.get('response_code'))),
                        page_text=row.get('Page Text', row.get('page_text'))
                    )
                    
                    self.db.add(result)
                    
                    # Check if IP is in scope
                    if ip_address:
                        matching_subnets = self.correlation_service.parser.find_matching_subnets(ip_address)
                        if not matching_subnets:
                            # Create out-of-scope entry
                            out_of_scope = models.OutOfScopeHost(
                                scan_id=scan.id,
                                ip_address=ip_address,
                                hostname=self._extract_hostname_from_url(url),
                                ports={'web': self._safe_int(row.get('Port', row.get('port', 80)))},
                                tool_source='eyewitness',
                                reason='IP address not found in any defined subnet scope'
                            )
                            self.db.add(out_of_scope)
                            out_of_scope_count += 1
                
                except Exception as e:
                    logger.warning(f"Error processing Eyewitness CSV row {row}: {str(e)}")
                    continue
        
        self.db.commit()
        
        logger.info(f"Processed {len(rows)} Eyewitness CSV results, {out_of_scope_count} out of scope")
        return scan

    def _extract_ip_from_url(self, url: str) -> Optional[str]:
        """Extract IP address from URL"""
        if not url:
            return None
        
        # Pattern to match IP addresses in URLs
        ip_pattern = r'://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
        match = re.search(ip_pattern, url)
        
        if match:
            return match.group(1)
        
        # If no IP found, try to extract hostname for DNS resolution later
        hostname_pattern = r'://([^:/]+)'
        hostname_match = re.search(hostname_pattern, url)
        if hostname_match:
            hostname = hostname_match.group(1)
            # Simple check if it's not an IP address
            if not re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', hostname):
                # This is a hostname, we might want to resolve it later
                return None
        
        return None

    def _extract_hostname_from_url(self, url: str) -> Optional[str]:
        """Extract hostname from URL"""
        if not url:
            return None
        
        hostname_pattern = r'://([^:/]+)'
        match = re.search(hostname_pattern, url)
        
        if match:
            return match.group(1)
        
        return None

    def _safe_int(self, value) -> Optional[int]:
        """Safely convert value to integer"""
        if value is None or value == '':
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None