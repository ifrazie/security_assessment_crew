from typing import List
from pydantic import BaseModel, Field

class PortInfo(BaseModel):
    """Details about a specific port"""
    port_number: int = Field(description="Port number")
    service_name: str = Field(description="Name of the service running on the port")
    state: str = Field(description="Current state of the port (open/filtered/closed)")
    risk_level: str = Field(description="Risk level (High/Medium/Low)")
    description: str = Field(description="Detailed description of the port and its risks")

class ScanOverview(BaseModel):
    """Summary of the scan results"""
    status: str = Field(description="Status of the scan")
    total_ports_scanned: int = Field(description="Number of ports scanned")
    scan_duration: str = Field(description="Duration of the scan")

class Recommendation(BaseModel):
    """Security recommendations"""
    title: str = Field(description="Title of the recommendation")
    details: str = Field(description="Detailed explanation of the recommendation")

class ReportOutline(BaseModel):
    """Structure for security assessment reports"""
    title: str = Field(description="Title of the report including target IP")
    scan_overview: ScanOverview = Field(description="Overview of the scan results")
    port_findings: List[PortInfo] = Field(description="Detailed findings for each port")
    recommendations: List[Recommendation] = Field(description="List of security recommendations")
    conclusion: str = Field(description="Overall summary and risk assessment")
