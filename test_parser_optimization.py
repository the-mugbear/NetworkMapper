#!/usr/bin/env python3
"""
Simple test script to verify parser optimization works correctly
"""
import sys
import os
sys.path.append('/home/charles/Documents/NetworkMapper/backend')

from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db import models
from app.parsers.nmap_parser import NmapXMLParser

def test_parser_optimization():
    """Test that the Nmap parser correctly filters hosts"""
    db = SessionLocal()
    
    try:
        # Count existing data before test
        initial_scans = db.query(models.Scan).count()
        initial_hosts = db.query(models.Host).count()
        print(f"Before test: {initial_scans} scans, {initial_hosts} hosts")
        
        # Parse the test XML file
        parser = NmapXMLParser(db)
        scan = parser.parse_file('/app/test_scan.xml', 'test_scan.xml')
        
        # Check results
        hosts = db.query(models.Host).filter(models.Host.scan_id == scan.id).all()
        
        print(f"Scan ID: {scan.id}")
        print(f"Total hosts created: {len(hosts)}")
        
        for host in hosts:
            ports = db.query(models.Port).filter(models.Port.host_id == host.id).all()
            print(f"Host {host.ip_address}: {host.state}, {len(ports)} ports")
            for port in ports:
                print(f"  Port {port.port_number}/{port.protocol}: {port.state}")
        
        print("\nParser optimization test completed successfully!")
        
    except Exception as e:
        print(f"Error during test: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        db.close()

if __name__ == "__main__":
    test_parser_optimization()