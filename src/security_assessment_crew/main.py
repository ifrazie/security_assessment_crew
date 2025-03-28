#!/usr/bin/env python
from typing import List
from pydantic import BaseModel
from crewai.flow import Flow, listen, start
from security_assessment_crew.crews.recon_crew.recon_crew import SecurityToolsCrew
from security_assessment_crew.utils.report_formatter import SecurityReportFormatter
from security_assessment_crew.models import PortInfo, ScanOverview, Recommendation, ReportOutline

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
        scan_result = (
            SecurityToolsCrew()
            .crew()
            .kickoff(inputs={"ip_address": self.state.ip_address})
        )
        
        # Parse scan results to extract port information
        self.state.scan_results = scan_result.raw
        
        # Parse ports from scan results
        port_findings = self._parse_scan_results(self.state.scan_results)
        
        # Initialize report structure
        self.state.report = ReportOutline(
            title=f"Security Posture Report for {self.state.ip_address}",
            scan_overview=ScanOverview(
                status="completed",
                total_ports_scanned=1024,
                scan_duration="7.98ms"
            ),
            port_findings=port_findings,
            recommendations=[
                Recommendation(
                    title="Access Controls",
                    details="Implement strict access controls and strong authentication mechanisms for SMB (Port 445)."
                ),
                Recommendation(
                    title="Updates",
                    details="Regularly update and patch systems to protect against known vulnerabilities."
                ),
                Recommendation(
                    title="Assessment",
                    details="Conduct vulnerability assessments and penetration testing to identify and remediate potential weaknesses."
                ),
                Recommendation(
                    title="Monitoring",
                    details="Monitor network traffic and logs for suspicious activities related to open ports."
                )
            ],
            conclusion="The security posture presents a mix of low, medium, and high risks. The most critical finding is the open SMB port (Port 445), which poses a high risk due to potential unauthorized access and data exfiltration. Addressing this vulnerability should be prioritized."
        )
        
        # Save formatted report
        report_content = SecurityReportFormatter.format_report(self.state.report)
        with open("output/security_report.md", "w", encoding='utf-8') as file:
            file.write(report_content)
        
        print("Port scan completed and report generated")

    def _parse_scan_results(self, scan_results: str) -> List[PortInfo]:
        """Parse scan results into structured port information"""
        # Add logic to parse scan results and create PortInfo objects
        # This is a placeholder - implement actual parsing based on your scan output
        return [
            PortInfo(
                port_number=445,
                service_name="microsoft-ds",
                state="open",
                risk_level="High",
                description="This port is used for Microsoft Server Message Block (SMB). An open SMB port can be exploited to gain unauthorized access, transfer files, and execute code on the host."
            ),
            # Add more ports based on scan results
        ]

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
