"""
Test script for v2 parser with deduplication

This script tests the new deduplication logic by:
1. Creating sample data with duplicate hosts
2. Testing parser deduplication
3. Validating data integrity
"""

import os
import sys
import logging
import tempfile
from pathlib import Path

# Add the backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.db import models
from app.db.models_v2 import Host, PortV2, HostScanHistory, PortScanHistory
from app.services.host_deduplication_service import HostDeduplicationService
from app.parsers.nmap_parser_v2 import NmapXMLParserV2
from app.core.feature_flags import feature_flags

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class V2ParserTester:
    """Test the v2 parser and deduplication logic"""
    
    def __init__(self):
        # Use in-memory SQLite for testing
        self.engine = create_engine("sqlite:///test_v2.db", echo=False)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Enable v2 features for testing
        feature_flags.set_flag('USE_V2_SCHEMA', True)
        feature_flags.set_flag('USE_V2_PARSER', True)
    
    def setup_database(self):
        """Create test database tables"""
        logger.info("Setting up test database...")
        
        # Create all tables (both v1 and v2 for testing)
        Base.metadata.create_all(bind=self.engine, checkfirst=True)
        
        logger.info("Test database setup complete")
    
    def test_deduplication_service(self):
        """Test the basic deduplication service functionality"""
        logger.info("Testing deduplication service...")
        
        with self.SessionLocal() as db:
            dedup_service = HostDeduplicationService(db)
            
            # Create a test scan
            scan = models.Scan(filename="test_scan.xml", scan_type="nmap")
            db.add(scan)
            db.flush()
            
            # Test host creation and deduplication
            host_data = {
                'hostname': 'test.example.com',
                'state': 'up',
                'os_name': 'Linux 4.15',
                'os_accuracy': 95
            }
            
            # First occurrence
            host1 = dedup_service.find_or_create_host('192.168.1.10', scan.id, host_data)
            db.commit()
            
            # Second occurrence (should reuse existing host)
            host_data2 = {
                'hostname': 'test.example.com',
                'state': 'up',
                'os_name': 'Linux 5.4',  # Better OS detection
                'os_accuracy': 98
            }
            host2 = dedup_service.find_or_create_host('192.168.1.10', scan.id, host_data2)
            db.commit()
            
            # Verify they're the same host
            assert host1.id == host2.id, "Hosts should be deduplicated"
            assert host2.os_name == 'Linux 5.4', "OS should be updated to better accuracy"
            assert host2.os_accuracy == 98, "OS accuracy should be updated"
            
            # Test port deduplication
            port_data = {
                'port_number': 80,
                'protocol': 'tcp',
                'state': 'open',
                'service_name': 'http'
            }
            
            port1 = dedup_service.find_or_create_port(host1.id, scan.id, port_data)
            db.commit()
            
            # Same port again (should reuse)
            port_data2 = {
                'port_number': 80,
                'protocol': 'tcp',
                'state': 'open',
                'service_name': 'http',
                'service_version': '2.4.41'  # Additional service info
            }
            port2 = dedup_service.find_or_create_port(host1.id, scan.id, port_data2)
            db.commit()
            
            assert port1.id == port2.id, "Ports should be deduplicated"
            assert port2.service_version == '2.4.41', "Service info should be updated"
            
            # Verify audit data
            history_count = db.query(HostScanHistory).count()
            assert history_count >= 1, "Should have audit history"
            
            port_history_count = db.query(PortScanHistory).count()
            assert port_history_count >= 1, "Should have port audit history"
            
            logger.info("✅ Deduplication service test passed!")
    
    def test_sample_xml_parsing(self):
        """Test parsing with a sample XML file"""
        logger.info("Testing XML parsing with deduplication...")
        
        # Create sample Nmap XML
        sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS 192.168.1.0/24" start="1641024000" startstr="Sat Jan  1 00:00:00 2022" version="7.91" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>

<host starttime="1641024000" endtime="1641024005">
<status state="up" reason="arp-response"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames>
<hostname name="webserver.local" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/>
</port>
</ports>
<os>
<osmatch name="Linux 4.15 - 5.6" accuracy="95" line="47043">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="95"/>
</osmatch>
</os>
</host>

<host starttime="1641024005" endtime="1641024010">
<status state="up" reason="arp-response"/>
<address addr="192.168.1.20" addrtype="ipv4"/>
<hostnames>
<hostname name="database.local" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="3306">
<state state="open" reason="syn-ack"/>
<service name="mysql" product="MySQL" version="8.0.27" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
</port>
</ports>
</host>

<runstats><finished time="1641024010" timestr="Sat Jan  1 00:00:10 2022" elapsed="10.00"/></runstats>
</nmaprun>'''
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(sample_xml)
            temp_file = f.name
        
        try:
            with self.SessionLocal() as db:
                parser = NmapXMLParserV2(db)
                scan = parser.parse_file(temp_file, "test_sample.xml")
                db.commit()
                
                # Verify results
                host_count = db.query(Host).count()
                port_count = db.query(PortV2).count()
                
                logger.info(f"Parsed: {host_count} hosts, {port_count} ports")
                
                # Verify specific hosts
                webserver = db.query(Host).filter(Host.ip_address == '192.168.1.10').first()
                assert webserver is not None, "Webserver should exist"
                assert webserver.hostname == 'webserver.local', "Hostname should match"
                assert len(webserver.ports) == 2, "Should have 2 ports"
                
                database = db.query(Host).filter(Host.ip_address == '192.168.1.20').first()
                assert database is not None, "Database server should exist"
                assert len(database.ports) == 2, "Should have 2 ports"
                
                # Test deduplication by parsing the same file again
                logger.info("Testing deduplication by parsing same file again...")
                scan2 = parser.parse_file(temp_file, "test_sample_duplicate.xml")
                db.commit()
                
                # Host count should remain the same (deduplicated)
                host_count_after = db.query(Host).count()
                assert host_count_after == host_count, f"Host count should remain {host_count}, got {host_count_after}"
                
                # Check audit history
                history_count = db.query(HostScanHistory).count()
                assert history_count == 4, f"Should have 4 host scan history entries (2 hosts x 2 scans), got {history_count}"
                
                logger.info("✅ XML parsing with deduplication test passed!")
                
        finally:
            # Clean up
            os.unlink(temp_file)
    
    def run_all_tests(self):
        """Run all tests"""
        logger.info("Starting v2 parser tests...")
        
        self.setup_database()
        self.test_deduplication_service()
        self.test_sample_xml_parsing()
        
        logger.info("🎉 All tests passed!")
    
    def cleanup(self):
        """Clean up test database"""
        try:
            os.unlink("test_v2.db")
            logger.info("Test database cleaned up")
        except:
            pass


def main():
    """Run the tests"""
    tester = V2ParserTester()
    
    try:
        tester.run_all_tests()
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise
    finally:
        tester.cleanup()


if __name__ == "__main__":
    main()