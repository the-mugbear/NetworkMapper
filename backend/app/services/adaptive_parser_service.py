"""
Adaptive Parser Service

Routes to appropriate parser version based on feature flags.
Supports gradual migration from v1 to v2 schema.
"""

import logging
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.db import models
from app.core.feature_flags import feature_flags
from app.parsers.nmap_parser import NmapXMLParser
from app.parsers.nmap_parser_v2 import NmapXMLParserV2

logger = logging.getLogger(__name__)


class AdaptiveParserService:
    """Routes parsing to appropriate version based on feature flags"""
    
    def __init__(self, db: Session):
        self.db = db
        self.v1_nmap_parser = NmapXMLParser(db)
        self.v2_nmap_parser = NmapXMLParserV2(db) if feature_flags.use_v2_parser else None
    
    def parse_nmap_file(self, file_path: str, filename: str) -> models.Scan:
        """Parse Nmap file using appropriate parser version"""
        
        if feature_flags.use_v2_parser and self.v2_nmap_parser:
            logger.info(f"Using v2 parser for {filename}")
            
            if feature_flags.dual_write_mode:
                # Dual write mode: parse with both versions for validation
                logger.info("Dual write mode enabled - parsing with both v1 and v2")
                
                try:
                    # Parse with v1 first (existing behavior)
                    scan_v1 = self.v1_nmap_parser.parse_file(file_path, f"{filename}_v1_backup")
                    
                    # Parse with v2
                    scan_v2 = self.v2_nmap_parser.parse_file(file_path, filename)
                    
                    # Log comparison metrics
                    self._compare_parse_results(scan_v1, scan_v2)
                    
                    # Return v2 result
                    return scan_v2
                    
                except Exception as e:
                    logger.error(f"Error in dual write mode: {e}")
                    # Fall back to v1 only
                    logger.info("Falling back to v1 parser only")
                    return self.v1_nmap_parser.parse_file(file_path, filename)
            else:
                # Pure v2 mode
                return self.v2_nmap_parser.parse_file(file_path, filename)
        else:
            # Use v1 parser
            logger.info(f"Using v1 parser for {filename}")
            return self.v1_nmap_parser.parse_file(file_path, filename)
    
    def parse_file_by_type(self, file_path: str, filename: str, file_type: str) -> models.Scan:
        """Parse file based on detected type"""
        
        if file_type.lower() in ['nmap', 'xml']:
            return self.parse_nmap_file(file_path, filename)
        else:
            # For other parsers, use existing logic (no v2 versions yet)
            logger.info(f"Using existing parser for {file_type}: {filename}")
            # This would route to other parsers like gnmap, masscan, etc.
            # For now, try nmap parser
            return self.parse_nmap_file(file_path, filename)
    
    def _compare_parse_results(self, scan_v1: models.Scan, scan_v2: models.Scan):
        """Compare results from v1 and v2 parsers for validation"""
        
        try:
            # Get host counts (v1 may have duplicates, v2 should not)
            v1_host_count = len(scan_v1.hosts) if hasattr(scan_v1, 'hosts') else 0
            
            # For v2, we need to count from the deduplicated hosts table
            from app.db.models_v2 import Host, HostScanHistory
            v2_unique_hosts = self.db.query(Host).join(HostScanHistory).filter(
                HostScanHistory.scan_id == scan_v2.id
            ).count()
            
            # Log comparison
            logger.info(f"Parse comparison - V1: {v1_host_count} host records, V2: {v2_unique_hosts} unique hosts")
            
            if feature_flags.is_enabled('DEBUG_DEDUPLICATION'):
                # More detailed comparison for debugging
                self._detailed_comparison(scan_v1, scan_v2)
                
        except Exception as e:
            logger.error(f"Error comparing parse results: {e}")
    
    def _detailed_comparison(self, scan_v1: models.Scan, scan_v2: models.Scan):
        """Detailed comparison for debugging"""
        
        try:
            # Get unique IPs from v1
            v1_ips = set()
            if hasattr(scan_v1, 'hosts'):
                v1_ips = {host.ip_address for host in scan_v1.hosts}
            
            # Get unique IPs from v2
            from app.db.models_v2 import Host, HostScanHistory
            v2_hosts = self.db.query(Host).join(HostScanHistory).filter(
                HostScanHistory.scan_id == scan_v2.id
            ).all()
            v2_ips = {host.ip_address for host in v2_hosts}
            
            # Compare IP sets
            only_in_v1 = v1_ips - v2_ips
            only_in_v2 = v2_ips - v1_ips
            
            if only_in_v1:
                logger.warning(f"IPs only in v1: {only_in_v1}")
            if only_in_v2:
                logger.warning(f"IPs only in v2: {only_in_v2}")
            
            # Count ports
            v1_port_count = 0
            if hasattr(scan_v1, 'hosts'):
                for host in scan_v1.hosts:
                    v1_port_count += len(host.ports) if hasattr(host, 'ports') else 0
            
            from app.db.models_v2 import PortV2, PortScanHistory
            v2_port_count = self.db.query(PortV2).join(PortScanHistory).filter(
                PortScanHistory.scan_id == scan_v2.id
            ).count()
            
            logger.info(f"Port comparison - V1: {v1_port_count} port records, V2: {v2_port_count} ports")
            
        except Exception as e:
            logger.error(f"Error in detailed comparison: {e}")
    
    def get_parser_info(self) -> Dict[str, Any]:
        """Get information about current parser configuration"""
        return {
            'use_v2_parser': feature_flags.use_v2_parser,
            'dual_write_mode': feature_flags.dual_write_mode,
            'migration_mode': feature_flags.migration_mode,
            'v2_parser_available': self.v2_nmap_parser is not None,
            'feature_flags': feature_flags.get_all_flags()
        }