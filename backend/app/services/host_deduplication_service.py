"""
Host Deduplication Service

Handles finding, creating, and updating host records to eliminate duplicates.
Implements conflict resolution and audit tracking for data changes.
"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db import models
from app.db.models import Host, Port, Script, HostScript, HostScanHistory, PortScanHistory


class HostDeduplicationService:
    """Service to manage host deduplication and merging across scans"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def find_or_create_host(self, ip_address: str, scan_id: int, host_data: Dict[str, Any]) -> Host:
        """
        Find existing host by IP or create new one.
        Updates existing host with new information using conflict resolution.
        """
        # Try to find existing host
        existing_host = self.db.query(Host).filter(Host.ip_address == ip_address).first()
        
        if existing_host:
            # Update existing host
            updated_host = self._update_existing_host(existing_host, scan_id, host_data)
            # Record this scan discovered the host
            self._record_host_scan_history(updated_host.id, scan_id, host_data)
            return updated_host
        else:
            # Create new host
            new_host = self._create_new_host(ip_address, scan_id, host_data)
            self.db.add(new_host)
            self.db.flush()  # Get the ID
            
            # Record initial scan history
            self._record_host_scan_history(new_host.id, scan_id, host_data, is_new=True)
            return new_host
    
    def find_or_create_port(self, host_id: int, scan_id: int, port_data: Dict[str, Any]) -> Port:
        """
        Find existing port by host_id + port_number + protocol or create new one.
        Updates existing port with new information.
        """
        port_number = port_data.get('port_number')
        protocol = port_data.get('protocol', 'tcp')
        
        # Try to find existing port
        existing_port = self.db.query(Port).filter(
            Port.host_id == host_id,
            Port.port_number == port_number,
            Port.protocol == protocol
        ).first()
        
        if existing_port:
            # Update existing port
            updated_port = self._update_existing_port(existing_port, scan_id, port_data)
            # Record port scan history
            self._record_port_scan_history(updated_port.id, scan_id, port_data)
            return updated_port
        else:
            # Create new port
            new_port = self._create_new_port(host_id, scan_id, port_data)
            self.db.add(new_port)
            self.db.flush()  # Get the ID
            
            # Record initial port scan history
            self._record_port_scan_history(new_port.id, scan_id, port_data, is_new=True)
            return new_port
    
    def add_or_update_script(self, port_id: int, scan_id: int, script_data: Dict[str, Any]) -> Script:
        """Add or update a script for a port"""
        script_id = script_data.get('script_id')
        output = script_data.get('output', '')
        
        # Try to find existing script
        existing_script = self.db.query(Script).filter(
            Script.port_id == port_id,
            Script.script_id == script_id
        ).first()
        
        if existing_script:
            # Update existing script
            existing_script.output = output
            existing_script.last_seen = func.now()
            existing_script.scan_id = scan_id  # Update to latest scan
            return existing_script
        else:
            # Create new script
            new_script = Script(
                port_id=port_id,
                script_id=script_id,
                output=output,
                scan_id=scan_id
            )
            self.db.add(new_script)
            return new_script
    
    def add_or_update_host_script(self, host_id: int, scan_id: int, script_data: Dict[str, Any]) -> HostScript:
        """Add or update a host script"""
        script_id = script_data.get('script_id')
        output = script_data.get('output', '')
        
        # Try to find existing host script
        existing_script = self.db.query(HostScript).filter(
            HostScript.host_id == host_id,
            HostScript.script_id == script_id
        ).first()
        
        if existing_script:
            # Update existing script
            existing_script.output = output
            existing_script.last_seen = func.now()
            existing_script.scan_id = scan_id  # Update to latest scan
            return existing_script
        else:
            # Create new host script
            new_script = HostScript(
                host_id=host_id,
                script_id=script_id,
                output=output,
                scan_id=scan_id
            )
            self.db.add(new_script)
            return new_script
    
    def _create_new_host(self, ip_address: str, scan_id: int, host_data: Dict[str, Any]) -> Host:
        """Create a new host record"""
        host = Host(
            ip_address=ip_address,
            hostname=host_data.get('hostname'),
            state=host_data.get('state'),
            state_reason=host_data.get('state_reason'),
            os_name=host_data.get('os_name'),
            os_family=host_data.get('os_family'),
            os_generation=host_data.get('os_generation'),
            os_type=host_data.get('os_type'),
            os_vendor=host_data.get('os_vendor'),
            os_accuracy=host_data.get('os_accuracy'),
            last_updated_scan_id=scan_id
        )
        return host
    
    def _update_existing_host(self, host: Host, scan_id: int, host_data: Dict[str, Any]) -> Host:
        """
        Update existing host with new data using conflict resolution strategy.
        Strategy: "Most recent wins" with some intelligence for better data.
        """
        updated = False
        
        # Update hostname if new one is provided and not null
        new_hostname = host_data.get('hostname')
        if new_hostname and (not host.hostname or len(new_hostname) > len(host.hostname or '')):
            host.hostname = new_hostname
            updated = True
        
        # Update state (most recent wins)
        new_state = host_data.get('state')
        if new_state and new_state != host.state:
            host.state = new_state
            host.state_reason = host_data.get('state_reason')
            updated = True
        
        # Update OS information if new scan has higher accuracy or we don't have OS info
        new_accuracy = host_data.get('os_accuracy', 0)
        if (not host.os_name or new_accuracy > (host.os_accuracy or 0)):
            if host_data.get('os_name'):
                host.os_name = host_data.get('os_name')
                host.os_family = host_data.get('os_family')
                host.os_generation = host_data.get('os_generation')
                host.os_type = host_data.get('os_type')
                host.os_vendor = host_data.get('os_vendor')
                host.os_accuracy = new_accuracy
                updated = True
        
        # Always update last seen and scan reference
        host.last_seen = func.now()
        host.last_updated_scan_id = scan_id
        
        return host
    
    def _create_new_port(self, host_id: int, scan_id: int, port_data: Dict[str, Any]) -> Port:
        """Create a new port record"""
        port = Port(
            host_id=host_id,
            port_number=port_data.get('port_number'),
            protocol=port_data.get('protocol', 'tcp'),
            state=port_data.get('state'),
            reason=port_data.get('reason'),
            service_name=port_data.get('service_name'),
            service_product=port_data.get('service_product'),
            service_version=port_data.get('service_version'),
            service_extrainfo=port_data.get('service_extrainfo'),
            service_method=port_data.get('service_method'),
            service_conf=port_data.get('service_conf'),
            last_updated_scan_id=scan_id,
            is_active=True
        )
        return port
    
    def _update_existing_port(self, port: Port, scan_id: int, port_data: Dict[str, Any]) -> Port:
        """
        Update existing port with new data using conflict resolution.
        Strategy: Keep most detailed/accurate service information.
        """
        # Update state (most recent wins)
        new_state = port_data.get('state')
        if new_state:
            port.state = new_state
            port.reason = port_data.get('reason')
            port.is_active = (new_state in ['open', 'filtered'])
        
        # Update service info if new scan has better information
        new_service_name = port_data.get('service_name')
        new_service_conf = port_data.get('service_conf', 0)
        
        # Use service info with higher confidence or if we don't have any
        if (not port.service_name or 
            new_service_conf > (port.service_conf or 0) or
            (new_service_name and len(new_service_name) > len(port.service_name or ''))):
            
            port.service_name = new_service_name
            port.service_product = port_data.get('service_product')
            port.service_version = port_data.get('service_version')
            port.service_extrainfo = port_data.get('service_extrainfo')
            port.service_method = port_data.get('service_method')
            port.service_conf = new_service_conf
        
        # Always update timestamps and scan reference
        port.last_seen = func.now()
        port.last_updated_scan_id = scan_id
        
        return port
    
    def _record_host_scan_history(self, host_id: int, scan_id: int, host_data: Dict[str, Any], is_new: bool = False):
        """Record that this scan discovered/updated this host"""
        history = HostScanHistory(
            host_id=host_id,
            scan_id=scan_id,
            state_at_scan=host_data.get('state'),
            hostname_at_scan=host_data.get('hostname'),
            os_info_updated=bool(host_data.get('os_name'))  # True if this scan provided OS info
        )
        self.db.add(history)
    
    def _record_port_scan_history(self, port_id: int, scan_id: int, port_data: Dict[str, Any], is_new: bool = False):
        """Record port state at time of this scan"""
        service_info = {
            'service_name': port_data.get('service_name'),
            'service_product': port_data.get('service_product'),
            'service_version': port_data.get('service_version'),
            'service_extrainfo': port_data.get('service_extrainfo'),
            'service_method': port_data.get('service_method'),
            'service_conf': port_data.get('service_conf')
        }
        
        history = PortScanHistory(
            port_id=port_id,
            scan_id=scan_id,
            state_at_scan=port_data.get('state'),
            service_info=json.dumps(service_info) if any(service_info.values()) else None
        )
        self.db.add(history)
    
    def update_scan_statistics(self, scan_id: int):
        """Update scan statistics after processing"""
        # Count hosts discovered in this scan
        hosts_discovered = self.db.query(HostScanHistory).filter(
            HostScanHistory.scan_id == scan_id
        ).count()
        
        # Count ports discovered in this scan 
        ports_discovered = self.db.query(PortScanHistory).filter(
            PortScanHistory.scan_id == scan_id
        ).count()
        
        # Count new hosts (first time seen)
        new_hosts = self.db.query(Host).filter(
            Host.last_updated_scan_id == scan_id,
            Host.first_seen == Host.last_seen  # First seen equals last seen means it's new
        ).count()
        
        # Update scan record
        scan = self.db.query(models.Scan).filter(models.Scan.id == scan_id).first()
        if scan:
            scan.hosts_discovered = hosts_discovered
            scan.ports_discovered = ports_discovered 
            scan.new_hosts = new_hosts
            scan.updated_hosts = hosts_discovered - new_hosts
            
    def get_host_statistics(self) -> Dict[str, int]:
        """Get overall host statistics"""
        total_hosts = self.db.query(Host).count()
        active_hosts = self.db.query(Host).filter(Host.state == 'up').count()
        total_ports = self.db.query(Port).count()
        open_ports = self.db.query(Port).filter(Port.state == 'open').count()
        
        return {
            'total_hosts': total_hosts,
            'active_hosts': active_hosts,
            'total_ports': total_ports,
            'open_ports': open_ports
        }