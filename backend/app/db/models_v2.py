"""
Database models v2 - Optimized schema with host deduplication

Key changes:
- Hosts are unique by IP address (no scan_id foreign key)
- Added tracking tables for scan history and data provenance
- Added timestamps for first/last seen tracking
- Ports are unique per host by port_number + protocol
- Added conflict resolution fields for host metadata
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, UniqueConstraint, Index, func
from sqlalchemy.orm import relationship
from app.db.base import Base


class Host(Base):
    __tablename__ = "hosts_v2"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False, unique=True, index=True)  # Now unique
    hostname = Column(String)
    state = Column(String)
    state_reason = Column(String)
    os_name = Column(String)
    os_family = Column(String) 
    os_generation = Column(String)
    os_type = Column(String)
    os_vendor = Column(String)
    os_accuracy = Column(Integer)
    
    # Audit fields
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_updated_scan_id = Column(Integer, ForeignKey("scans.id"))  # Track which scan last updated this host
    
    # Relationships
    ports = relationship("PortV2", back_populates="host", cascade="all, delete-orphan")
    host_scripts = relationship("HostScriptV2", back_populates="host", cascade="all, delete-orphan") 
    scan_history = relationship("HostScanHistory", back_populates="host", cascade="all, delete-orphan")
    last_updated_scan = relationship("Scan", foreign_keys=[last_updated_scan_id])

    __table_args__ = (
        Index('idx_host_ip_address', 'ip_address'),
    )


class PortV2(Base):
    __tablename__ = "ports_v2"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts_v2.id"), nullable=False)
    port_number = Column(Integer, nullable=False, index=True)
    protocol = Column(String, nullable=False)
    state = Column(String)
    reason = Column(String)
    service_name = Column(String)
    service_product = Column(String)
    service_version = Column(String)
    service_extrainfo = Column(Text)
    service_method = Column(String)
    service_conf = Column(Integer)
    
    # Audit fields
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_updated_scan_id = Column(Integer, ForeignKey("scans.id"))
    is_active = Column(Boolean, default=True)  # Track if port is currently active
    
    # Relationships
    host = relationship("Host", back_populates="ports")
    scripts = relationship("ScriptV2", back_populates="port", cascade="all, delete-orphan")
    last_updated_scan = relationship("Scan", foreign_keys=[last_updated_scan_id])

    __table_args__ = (
        UniqueConstraint('host_id', 'port_number', 'protocol', name='uq_host_port_protocol'),
        Index('idx_port_number_protocol', 'port_number', 'protocol'),
        Index('idx_port_state', 'state'),
    )


class ScriptV2(Base):
    __tablename__ = "scripts_v2"

    id = Column(Integer, primary_key=True, index=True)
    port_id = Column(Integer, ForeignKey("ports_v2.id"), nullable=False)
    script_id = Column(String, nullable=False)
    output = Column(Text)
    
    # Audit fields
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Relationships
    port = relationship("PortV2", back_populates="scripts")
    scan = relationship("Scan")

    __table_args__ = (
        UniqueConstraint('port_id', 'script_id', name='uq_port_script'),
        Index('idx_script_id', 'script_id'),
    )


class HostScriptV2(Base):
    __tablename__ = "host_scripts_v2"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts_v2.id"), nullable=False)
    script_id = Column(String, nullable=False)
    output = Column(Text)
    
    # Audit fields
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now()) 
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Relationships
    host = relationship("Host", back_populates="host_scripts")
    scan = relationship("Scan")

    __table_args__ = (
        UniqueConstraint('host_id', 'script_id', name='uq_host_script'),
        Index('idx_host_script_id', 'script_id'),
    )


class HostScanHistory(Base):
    """Track which scans have seen each host for audit purposes"""
    __tablename__ = "host_scan_history"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts_v2.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Host state at time of this scan
    state_at_scan = Column(String)
    hostname_at_scan = Column(String)
    os_info_updated = Column(Boolean, default=False)  # Whether this scan updated OS info
    
    # Relationships
    host = relationship("Host", back_populates="scan_history")
    scan = relationship("Scan")

    __table_args__ = (
        UniqueConstraint('host_id', 'scan_id', name='uq_host_scan'),
        Index('idx_host_scan_discovered', 'discovered_at'),
    )


class PortScanHistory(Base):
    """Track port state changes over time"""
    __tablename__ = "port_scan_history"

    id = Column(Integer, primary_key=True, index=True)
    port_id = Column(Integer, ForeignKey("ports_v2.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Port state at time of this scan
    state_at_scan = Column(String)
    service_info = Column(Text)  # JSON of service details at this scan
    
    # Relationships
    port = relationship("PortV2")
    scan = relationship("Scan")

    __table_args__ = (
        UniqueConstraint('port_id', 'scan_id', name='uq_port_scan'),
        Index('idx_port_scan_discovered', 'discovered_at'),
    )


# Update existing Scan model to work with new schema
class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    scan_type = Column(String)
    start_time = Column(DateTime(timezone=True))
    end_time = Column(DateTime(timezone=True))
    command_line = Column(Text)
    version = Column(String)
    xml_output_version = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Statistics (computed after parsing)
    hosts_discovered = Column(Integer, default=0)
    ports_discovered = Column(Integer, default=0)
    new_hosts = Column(Integer, default=0)  # Hosts first seen in this scan
    updated_hosts = Column(Integer, default=0)  # Hosts with updated info
    
    # Relationships
    scan_info = relationship("ScanInfo", back_populates="scan", cascade="all, delete-orphan")
    host_scan_history = relationship("HostScanHistory", back_populates="scan")
    port_scan_history = relationship("PortScanHistory", back_populates="scan")