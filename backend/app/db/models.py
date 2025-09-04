from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    scan_type = Column(String)  # nmap, eyewitness, masscan, etc.
    tool_name = Column(String)  # The specific tool used
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    command_line = Column(Text)
    version = Column(String)
    xml_output_version = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    scan_info = relationship("ScanInfo", back_populates="scan", cascade="all, delete-orphan")
    eyewitness_results = relationship("EyewitnessResult", back_populates="scan", cascade="all, delete-orphan")

class ScanInfo(Base):
    __tablename__ = "scan_info"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    type = Column(String)
    protocol = Column(String)
    numservices = Column(Integer)
    services = Column(Text)
    
    # Relationships
    scan = relationship("Scan", back_populates="scan_info")

class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    ip_address = Column(String, nullable=False, index=True)
    hostname = Column(String)
    state = Column(String)
    state_reason = Column(String)
    os_name = Column(String)
    os_family = Column(String)
    os_generation = Column(String)
    os_type = Column(String)
    os_vendor = Column(String)
    os_accuracy = Column(Integer)
    
    # Relationships
    scan = relationship("Scan", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    host_scripts = relationship("HostScript", back_populates="host", cascade="all, delete-orphan")

class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
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
    
    # Relationships
    host = relationship("Host", back_populates="ports")
    scripts = relationship("Script", back_populates="port", cascade="all, delete-orphan")

class Script(Base):
    __tablename__ = "scripts"

    id = Column(Integer, primary_key=True, index=True)
    port_id = Column(Integer, ForeignKey("ports.id"), nullable=False)
    script_id = Column(String, nullable=False)
    output = Column(Text)
    
    # Relationships
    port = relationship("Port", back_populates="scripts")

class HostScript(Base):
    __tablename__ = "host_scripts"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    script_id = Column(String, nullable=False)
    output = Column(Text)
    
    # Relationships
    host = relationship("Host", back_populates="host_scripts")

class Scope(Base):
    __tablename__ = "scopes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    subnets = relationship("Subnet", back_populates="scope", cascade="all, delete-orphan")

class Subnet(Base):
    __tablename__ = "subnets"

    id = Column(Integer, primary_key=True, index=True)
    scope_id = Column(Integer, ForeignKey("scopes.id"), nullable=False)
    cidr = Column(String, nullable=False, index=True)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scope = relationship("Scope", back_populates="subnets")
    host_mappings = relationship("HostSubnetMapping", back_populates="subnet", cascade="all, delete-orphan")

class HostSubnetMapping(Base):
    __tablename__ = "host_subnet_mappings"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    subnet_id = Column(Integer, ForeignKey("subnets.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    host = relationship("Host")
    subnet = relationship("Subnet", back_populates="host_mappings")

class EyewitnessResult(Base):
    __tablename__ = "eyewitness_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    url = Column(String, nullable=False, index=True)
    protocol = Column(String)
    port = Column(Integer)
    ip_address = Column(String, index=True)
    title = Column(String)
    server_header = Column(String)
    content_length = Column(Integer)
    screenshot_path = Column(String)
    response_code = Column(Integer)
    page_text = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="eyewitness_results")

class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, nullable=False, index=True)
    record_type = Column(String, nullable=False)  # A, AAAA, CNAME, MX, TXT, etc.
    value = Column(String, nullable=False)
    ttl = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class OutOfScopeHost(Base):
    __tablename__ = "out_of_scope_hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    ip_address = Column(String, nullable=False, index=True)
    hostname = Column(String)
    ports = Column(JSON)  # Store port information as JSON
    tool_source = Column(String)  # Which tool found this host
    reason = Column(String)  # Why it's out of scope
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan")