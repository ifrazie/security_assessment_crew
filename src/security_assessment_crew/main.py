#!/usr/bin/env python
from pydantic import BaseModel
from crewai.flow import Flow, listen, start
from security_assessment_crew.crews.recon_crew.recon_crew import SecurityToolsCrew

ip_address = '192.168.4.29'

class ScanState(BaseModel):
    ip_address: str = ""
    scan_results: str = ""


class SecurityScanFlow(Flow[ScanState]):
    @start()
    def initialize_scan(self):
        print("Initializing port scan")
        # You could set a different default IP here if needed
        self.state.ip_address = ip_address

    @listen(initialize_scan)
    def perform_scan(self):
        print(f"Scanning IP: {self.state.ip_address}")
        result = (
            SecurityToolsCrew()
            .crew()
            .kickoff(inputs={"ip_address": self.state.ip_address})
        )
        print("Port scan completed")
        self.state.scan_results = result.raw


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
