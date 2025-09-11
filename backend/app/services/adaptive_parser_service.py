"""
Parser Service

Handles file parsing using the current parser implementations.
"""

import logging
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.db import models
from app.parsers.nmap_parser import NmapXMLParser

logger = logging.getLogger(__name__)


class ParserService:
    """Handles file parsing with current parser implementations"""
    
    def __init__(self, db: Session):
        self.db = db
        self.nmap_parser = NmapXMLParser(db)
    
    def parse_nmap_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Nmap file"""
        logger.info(f"Parsing Nmap file: {filename}")
        return self.nmap_parser.parse_file(file_path, filename)
    
    def parse_file_by_type(self, file_path: str, filename: str, file_type: str) -> models.Scan:
        """Parse file based on detected type"""
        
        if file_type.lower() in ['nmap', 'xml']:
            return self.parse_nmap_file(file_path, filename)
        else:
            # For other parsers, route to appropriate parser
            logger.info(f"Parsing {file_type} file: {filename}")
            # For now, default to nmap parser for XML files
            return self.parse_nmap_file(file_path, filename)
    
    def get_parser_info(self) -> Dict[str, Any]:
        """Get information about current parser configuration"""
        return {
            'nmap_parser_available': True,
            'parsers': ['nmap_xml', 'gnmap', 'masscan', 'eyewitness', 'dns']
        }