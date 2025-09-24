from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from enum import Enum

class ScriptBase(BaseModel):
    script_id: str
    output: Optional[str] = None

class Script(ScriptBase):
    id: int
    port_id: int
    scan_id: int
    
    class Config:
        from_attributes = True

class HostScriptBase(BaseModel):
    script_id: str
    output: Optional[str] = None

class HostScript(HostScriptBase):
    id: int
    host_id: int
    scan_id: int
    
    class Config:
        from_attributes = True

class PortBase(BaseModel):
    port_number: int
    protocol: str
    state: Optional[str] = None
    reason: Optional[str] = None
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extrainfo: Optional[str] = None
    service_method: Optional[str] = None
    service_conf: Optional[int] = None

class Port(PortBase):
    id: int
    host_id: int
    last_updated_scan_id: Optional[int] = None
    scripts: List[Script] = []
    
    class Config:
        from_attributes = True

class HostBase(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    state: Optional[str] = None
    state_reason: Optional[str] = None
    os_name: Optional[str] = None
    os_family: Optional[str] = None
    os_generation: Optional[str] = None
    os_type: Optional[str] = None
    os_vendor: Optional[str] = None
    os_accuracy: Optional[int] = None


class FollowStatus(str, Enum):
    watching = "watching"
    in_review = "in_review"
    reviewed = "reviewed"


class NoteStatus(str, Enum):
    open = "open"
    in_progress = "in_progress"
    resolved = "resolved"


class HostFollowInfo(BaseModel):
    status: FollowStatus
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class HostNoteBase(BaseModel):
    body: str
    status: NoteStatus = NoteStatus.open


class HostNote(HostNoteBase):
    id: int
    author_id: int
    author_name: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class NoteActivityEntry(BaseModel):
    note_id: int
    host_id: int
    ip_address: str
    hostname: Optional[str] = None
    status: NoteStatus
    preview: str
    created_at: datetime
    updated_at: Optional[datetime] = None


class NoteActivitySummary(BaseModel):
    total_notes: int
    active_host_count: int
    following_count: int
    recent_notes: List[NoteActivityEntry] = []


class HostFollowUpdate(BaseModel):
    status: FollowStatus


class HostNoteCreate(HostNoteBase):
    status: NoteStatus = NoteStatus.open


class HostNoteUpdate(BaseModel):
    body: Optional[str] = None
    status: Optional[NoteStatus] = None

class HostVulnerabilitySummary(BaseModel):
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class Host(HostBase):
    id: int
    last_updated_scan_id: Optional[int] = None
    ports: List[Port] = []
    host_scripts: List[HostScript] = []
    vulnerability_summary: Optional[HostVulnerabilitySummary] = None
    follow: Optional[HostFollowInfo] = None
    notes: List[HostNote] = []
    note_count: int = 0

    class Config:
        from_attributes = True

class ScanInfoBase(BaseModel):
    type: Optional[str] = None
    protocol: Optional[str] = None
    numservices: Optional[int] = None
    services: Optional[str] = None

class ScanInfo(ScanInfoBase):
    id: int
    scan_id: int
    
    class Config:
        from_attributes = True

class ScanBase(BaseModel):
    filename: str
    scan_type: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    command_line: Optional[str] = None
    version: Optional[str] = None
    xml_output_version: Optional[str] = None

class Scan(ScanBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    hosts: List[Host] = []
    scan_info: List[ScanInfo] = []
    
    class Config:
        from_attributes = True

class ScanSummary(BaseModel):
    id: int
    filename: str
    scan_type: Optional[str] = None
    tool_name: Optional[str] = None
    created_at: datetime
    total_hosts: int
    up_hosts: int
    total_ports: int
    open_ports: int
    
    class Config:
        from_attributes = True

class SubnetStats(BaseModel):
    id: int
    cidr: str
    scope_name: str
    description: Optional[str] = None
    host_count: int
    total_addresses: Optional[int] = None
    usable_addresses: Optional[int] = None
    utilization_percentage: Optional[float] = None
    risk_level: Optional[str] = None
    network_address: Optional[str] = None
    is_private: Optional[bool] = None
    
    class Config:
        from_attributes = True

class VulnerabilityStats(BaseModel):
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    hosts_with_vulnerabilities: int

class DashboardStats(BaseModel):
    total_scans: int
    total_hosts: int
    total_ports: int
    up_hosts: int
    open_ports: int
    total_subnets: int
    recent_scans: List[ScanSummary]
    subnet_stats: List[SubnetStats]
    vulnerability_stats: Optional[VulnerabilityStats] = None
    note_activity: Optional[NoteActivitySummary] = None


class PortOfInterestSummary(BaseModel):
    port: int
    protocol: str
    label: str
    category: str
    weight: int
    open_host_count: int
    rationale: str
    recommended_action: str


class PortOfInterestHostEntry(BaseModel):
    port: int
    protocol: str
    label: str
    service: str
    weight: int
    category: str


class HostRiskExposure(BaseModel):
    host_id: int
    ip_address: str
    hostname: Optional[str] = None
    ports_of_interest: List[PortOfInterestHostEntry]
    critical: int
    high: int
    medium: int
    low: int
    risk_score: int
    port_score: int
    vulnerability_score: int


class VulnerabilityHotspot(BaseModel):
    host_id: int
    ip_address: str
    hostname: Optional[str] = None
    critical: int
    high: int
    medium: int
    low: int
    risk_score: int


class PortsOfInterestInsights(BaseModel):
    summary: List[PortOfInterestSummary]
    top_hosts: List[HostRiskExposure]


class RiskInsightResponse(BaseModel):
    ports_of_interest: PortsOfInterestInsights
    vulnerability_hotspots: List[VulnerabilityHotspot]

class FileUploadResponse(BaseModel):
    job_id: int
    filename: str
    status: str
    message: str
    scan_id: Optional[int] = None


class IngestionJobSchema(BaseModel):
    id: int
    filename: str
    original_filename: str
    status: str
    message: Optional[str] = None
    error_message: Optional[str] = None
    tool_name: Optional[str] = None
    file_size: Optional[int] = None
    scan_id: Optional[int] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class SubnetBase(BaseModel):
    cidr: str
    description: Optional[str] = None

class Subnet(SubnetBase):
    id: int
    scope_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class ScopeBase(BaseModel):
    name: str
    description: Optional[str] = None

class ScopeCreate(ScopeBase):
    pass

class Scope(ScopeBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    subnets: List[Subnet] = []
    
    class Config:
        from_attributes = True

class ScopeSummary(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    subnet_count: int
    
    class Config:
        from_attributes = True

class HostSubnetMapping(BaseModel):
    id: int
    host_id: int
    subnet_id: int
    created_at: datetime
    subnet: Subnet
    
    class Config:
        from_attributes = True

class SubnetFileUploadResponse(BaseModel):
    message: str
    scope_id: int
    subnets_added: int
    filename: str

class EyewitnessResultBase(BaseModel):
    url: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    ip_address: Optional[str] = None
    title: Optional[str] = None
    server_header: Optional[str] = None
    content_length: Optional[int] = None
    screenshot_path: Optional[str] = None
    response_code: Optional[int] = None
    page_text: Optional[str] = None

class EyewitnessResult(EyewitnessResultBase):
    id: int
    scan_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class DNSRecordBase(BaseModel):
    domain: str
    record_type: str
    value: str
    ttl: Optional[int] = None

class DNSRecord(DNSRecordBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class OutOfScopeHostBase(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    ports: Optional[dict] = None
    tool_source: Optional[str] = None
    reason: Optional[str] = None

class OutOfScopeHost(OutOfScopeHostBase):
    id: int
    scan_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class ParseErrorBase(BaseModel):
    filename: str
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    error_type: str
    error_message: str
    error_details: Optional[dict] = None
    file_preview: Optional[str] = None
    user_message: Optional[str] = None
    status: Optional[str] = "unresolved"

class ParseErrorCreate(ParseErrorBase):
    pass

class ParseError(ParseErrorBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class ParseErrorSummary(BaseModel):
    id: int
    filename: str
    file_type: Optional[str] = None
    error_type: str
    user_message: Optional[str] = None
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True
