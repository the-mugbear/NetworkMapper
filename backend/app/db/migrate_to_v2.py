"""
Migration script to convert from old schema to new deduplicated schema

This script:
1. Creates new v2 tables
2. Migrates existing data with deduplication
3. Preserves scan history and audit information
4. Can be run safely multiple times (idempotent)
"""

import logging
from datetime import datetime
from typing import Dict, Set
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.base import Base
from app.db import models
from app.db.models_v2 import Host, PortV2, ScriptV2, HostScriptV2, HostScanHistory, PortScanHistory
from app.services.host_deduplication_service import HostDeduplicationService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SchemaV2Migrator:
    """Handles migration from v1 to v2 schema"""
    
    def __init__(self, db_url: str = None):
        self.db_url = db_url or settings.SQLALCHEMY_DATABASE_URL
        self.engine = create_engine(self.db_url)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def migrate(self):
        """Run the complete migration process"""
        logger.info("Starting migration to v2 schema...")
        
        # 1. Create v2 tables
        self._create_v2_tables()
        
        # 2. Migrate data
        with self.SessionLocal() as db:
            dedup_service = HostDeduplicationService(db)
            
            # Get all scans in chronological order
            scans = db.query(models.Scan).order_by(models.Scan.created_at).all()
            logger.info(f"Found {len(scans)} scans to migrate")
            
            for scan in scans:
                logger.info(f"Migrating scan {scan.id}: {scan.filename}")
                self._migrate_scan(db, dedup_service, scan)
                
                # Update scan statistics
                dedup_service.update_scan_statistics(scan.id)
                
                # Commit after each scan
                db.commit()
                logger.info(f"Completed scan {scan.id}")
            
            logger.info("Migration completed successfully!")
            
            # Print statistics
            stats = dedup_service.get_host_statistics()
            logger.info(f"Migration results: {stats}")
    
    def _create_v2_tables(self):
        """Create the v2 table structure"""
        logger.info("Creating v2 tables...")
        
        # Import all v2 models to ensure they're registered
        from app.db.models_v2 import Host, PortV2, ScriptV2, HostScriptV2, HostScanHistory, PortScanHistory
        
        # Create tables
        Base.metadata.create_all(bind=self.engine, checkfirst=True)
        logger.info("V2 tables created")
    
    def _migrate_scan(self, db, dedup_service: HostDeduplicationService, scan: models.Scan):
        """Migrate a single scan's data"""
        
        # Get all hosts from this scan
        hosts = db.query(models.Host).filter(models.Host.scan_id == scan.id).all()
        
        for old_host in hosts:
            # Prepare host data
            host_data = {
                'hostname': old_host.hostname,
                'state': old_host.state,
                'state_reason': old_host.state_reason,
                'os_name': old_host.os_name,
                'os_family': old_host.os_family,
                'os_generation': old_host.os_generation,
                'os_type': old_host.os_type,
                'os_vendor': old_host.os_vendor,
                'os_accuracy': old_host.os_accuracy,
            }
            
            # Find or create deduplicated host
            new_host = dedup_service.find_or_create_host(
                old_host.ip_address, 
                scan.id, 
                host_data
            )
            
            # Migrate ports
            self._migrate_host_ports(db, dedup_service, old_host, new_host, scan.id)
            
            # Migrate host scripts
            self._migrate_host_scripts(db, dedup_service, old_host, new_host, scan.id)
    
    def _migrate_host_ports(self, db, dedup_service: HostDeduplicationService, 
                           old_host: models.Host, new_host: Host, scan_id: int):
        """Migrate ports for a host"""
        
        for old_port in old_host.ports:
            # Prepare port data
            port_data = {
                'port_number': old_port.port_number,
                'protocol': old_port.protocol,
                'state': old_port.state,
                'reason': old_port.reason,
                'service_name': old_port.service_name,
                'service_product': old_port.service_product,
                'service_version': old_port.service_version,
                'service_extrainfo': old_port.service_extrainfo,
                'service_method': old_port.service_method,
                'service_conf': old_port.service_conf,
            }
            
            # Find or create deduplicated port
            new_port = dedup_service.find_or_create_port(
                new_host.id,
                scan_id,
                port_data
            )
            
            # Migrate port scripts
            self._migrate_port_scripts(db, dedup_service, old_port, new_port, scan_id)
    
    def _migrate_port_scripts(self, db, dedup_service: HostDeduplicationService,
                             old_port: models.Port, new_port: PortV2, scan_id: int):
        """Migrate scripts for a port"""
        
        for old_script in old_port.scripts:
            script_data = {
                'script_id': old_script.script_id,
                'output': old_script.output
            }
            
            dedup_service.add_or_update_script(new_port.id, scan_id, script_data)
    
    def _migrate_host_scripts(self, db, dedup_service: HostDeduplicationService,
                             old_host: models.Host, new_host: Host, scan_id: int):
        """Migrate host scripts"""
        
        for old_script in old_host.host_scripts:
            script_data = {
                'script_id': old_script.script_id,
                'output': old_script.output
            }
            
            dedup_service.add_or_update_host_script(new_host.id, scan_id, script_data)
    
    def rollback_migration(self):
        """Rollback migration by dropping v2 tables"""
        logger.warning("Rolling back migration - dropping v2 tables...")
        
        with self.engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS port_scan_history CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS host_scan_history CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS host_scripts_v2 CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS scripts_v2 CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS ports_v2 CASCADE"))
            conn.execute(text("DROP TABLE IF EXISTS hosts_v2 CASCADE"))
            conn.commit()
        
        logger.info("Migration rolled back")
    
    def verify_migration(self):
        """Verify the migration was successful"""
        logger.info("Verifying migration...")
        
        with self.SessionLocal() as db:
            # Count records in old vs new schema
            old_host_count = db.query(models.Host).count()
            new_host_count = db.query(Host).count()
            
            old_port_count = db.query(models.Port).count()
            new_port_count = db.query(PortV2).count()
            
            logger.info(f"Old schema: {old_host_count} hosts, {old_port_count} ports")
            logger.info(f"New schema: {new_host_count} hosts, {new_port_count} ports")
            
            # Verify we have audit data
            history_count = db.query(HostScanHistory).count()
            port_history_count = db.query(PortScanHistory).count()
            
            logger.info(f"Audit data: {history_count} host scan entries, {port_history_count} port scan entries")
            
            # Check for any duplicate IPs (should be 0)
            duplicate_ips = db.execute(text("""
                SELECT ip_address, COUNT(*) 
                FROM hosts_v2 
                GROUP BY ip_address 
                HAVING COUNT(*) > 1
            """)).fetchall()
            
            if duplicate_ips:
                logger.error(f"Found duplicate IPs: {duplicate_ips}")
                return False
            else:
                logger.info("No duplicate IPs found - migration successful!")
                return True


def main():
    """CLI entry point for migration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Migrate to v2 schema with host deduplication')
    parser.add_argument('action', choices=['migrate', 'rollback', 'verify'], 
                       help='Action to perform')
    parser.add_argument('--db-url', help='Database URL (optional)')
    
    args = parser.parse_args()
    
    migrator = SchemaV2Migrator(args.db_url)
    
    if args.action == 'migrate':
        migrator.migrate()
    elif args.action == 'rollback':
        migrator.rollback_migration()
    elif args.action == 'verify':
        migrator.verify_migration()


if __name__ == "__main__":
    main()