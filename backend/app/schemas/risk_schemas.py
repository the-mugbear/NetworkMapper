"""
Risk Assessment Pydantic Schemas

Data models for risk assessment API endpoints.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class VulnerabilityBase(BaseModel):
    cve_id: str
    title: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: str
    exploitability: Optional[str] = None
    affected_software: Optional[str] = None
    affected_version: Optional[str] = None
    port_number: Optional[int] = None
    service_name: Optional[str] = None
    patch_available: bool = False
    patch_url: Optional[str] = None


class VulnerabilityResponse(VulnerabilityBase):
    id: int
    discovery_date: datetime
    source: str

    class Config:
        from_attributes = True


class SecurityFindingBase(BaseModel):
    finding_type: str
    title: str
    description: str
    severity: str
    risk_score: float
    evidence: Optional[str] = None
    affected_component: Optional[str] = None
    recommendation: Optional[str] = None


class SecurityFindingResponse(SecurityFindingBase):
    id: int
    discovery_date: datetime
    source: str

    class Config:
        from_attributes = True


class HostRiskAssessmentBase(BaseModel):
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: str
    vulnerability_count: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    exposed_services: int = 0
    dangerous_ports: int = 0
    attack_surface_score: float = 0.0
    patch_urgency_score: float = 0.0
    exposure_risk_score: float = 0.0
    configuration_risk_score: float = 0.0
    risk_summary: Optional[str] = None


class HostRiskAssessmentResponse(HostRiskAssessmentBase):
    id: int
    host_id: int
    assessment_date: datetime
    last_updated: datetime

    class Config:
        from_attributes = True


class HostRiskAnalysisResponse(BaseModel):
    """Complete host risk analysis response"""
    host: Dict[str, Any]
    risk_assessment: HostRiskAssessmentResponse
    vulnerabilities: Dict[str, List[VulnerabilityResponse]]
    security_findings: Dict[str, List[SecurityFindingResponse]]
    recommendations: List[str]
    summary_stats: Dict[str, int]


class RiskSummaryResponse(BaseModel):
    """Dashboard risk summary response"""
    total_hosts: int
    assessed_hosts: int
    unassessed_hosts: int
    risk_distribution: Dict[str, int]
    risk_percentages: Dict[str, float]
    top_risk_hosts: List[Dict[str, Any]]


class HighRiskHostResponse(BaseModel):
    """High-risk host summary for dashboard"""
    host_id: int
    ip_address: str
    hostname: Optional[str]
    os_name: Optional[str]
    risk_score: float
    risk_level: str
    vulnerability_count: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    risk_summary: Optional[str]
    top_vulnerabilities: List[Dict[str, Any]]
    critical_findings: List[Dict[str, Any]]
    recommendations: List[str]


class RiskAssessmentRequest(BaseModel):
    """Request to trigger risk assessment"""
    include_vulnerability_scan: bool = True
    include_configuration_analysis: bool = True
    force_refresh: bool = False