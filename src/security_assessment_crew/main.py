#!/usr/bin/env python
from typing import List, Optional
from pydantic import BaseModel, Field
from crewai.flow import Flow, listen, start
from security_assessment_crew.crews.recon_crew.recon_crew import SecurityToolsCrew
import json

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

class ScanState(BaseModel):
    ip_address: str = ""
    scan_results: str = ""
    report: ReportOutline = None

class SecurityScanFlow(Flow[ScanState]):
    @start()
    def initialize_scan(self):
        """Get input from about which ip_address to scan"""
        
        # Get the IP address from the user
        self.state.ip_address = input("Enter the IP address to scan:> ")
        print("<<<<< Initializing port scan >>>>>")

    @listen(initialize_scan)
    def perform_scan(self):
        """Perform a port scan on the target ip_address"""
        print(f"Scanning : {self.state.ip_address} for open ports")
        result = (
            SecurityToolsCrew()
            .crew()
            .kickoff(inputs={"ip_address": self.state.ip_address})
        )
        
        # Parse and store results
        self.state.scan_results = result.raw
        
        # Initialize report structure
        self.state.report = ReportOutline(
            title=f"Security Posture Report for {self.state.ip_address}",
            scan_overview=ScanOverview(
                status="completed",
                total_ports_scanned=1024,
                scan_duration="Scan completed successfully"
            ),
            port_findings=[],
            recommendations=[
                Recommendation(
                    title="Implement Access Controls",
                    details="Implement strict access controls and strong authentication mechanisms."
                )
            ],
            conclusion="Initial scan completed. See detailed findings above."
        )
        
        # Save raw results
        with open("output/nmap_scan.json", "w", encoding='utf-8') as file:
            json.dump(self.state.scan_results, file, indent=2)
        
        print("Port scan completed")

    @listen(perform_scan)
    def create_report(self):
        """Create a report based on the scan results"""
        print(f"Creating report for {self.state.ip_address}")
        
        try:
            result = (
                SecurityToolsCrew()
                .crew()
                .kickoff(inputs={
                    "ip_address": self.state.ip_address,
                    "scan_results": self.state.scan_results,
                    "report": self.state.report.model_dump()
                })
            )
            
            # Save the report with UTF-8 encoding
            with open("output/security_report.md", "w", encoding='utf-8') as file:
                file.write(result.raw if hasattr(result, 'raw') else result)
            
            print("Report created successfully")
            
        except Exception as e:
            print(f"Error creating report: {str(e)}")
            # Create basic report on error
            with open("output/security_report.md", "w", encoding='utf-8') as file:
                file.write(f"# Scan Report Error\nError generating report for {self.state.ip_address}")

def kickoff():
    """Run the security scan flow"""
    SecurityScanFlow().kickoff()
    print("\n*** Flow Completed ***\n")
    print("Results saved\n")
    print("Open output/nmap_scan.json to view the results\n")
    print("Open output/security_report.md to view the report\n")


def plot():
    """Print a viz of the flow"""
    flow = SecurityScanFlow()
    flow.plot("sec_flow")
    print("\n*** Flow Plot Generated ***\n")
    print("Results saved")
    print("Flow visualization saved to sec_flow.html")

if __name__ == "__main__":
    kickoff()
