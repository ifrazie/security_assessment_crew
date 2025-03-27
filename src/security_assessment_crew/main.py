#!/usr/bin/env python
from pydantic import BaseModel, Field
from crewai.flow import Flow, listen, start
from security_assessment_crew.crews.recon_crew.recon_crew import SecurityToolsCrew
import json

class ScanState(BaseModel):
    ip_address: str = ""
    scan_results: str = ""

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
        # Save the scan results to a file
        with open("output/nmap_scan.json", "w") as file:
            json.dump(result.raw, file, indent=2)
        
        # Store results in state
        self.state.scan_results = result.raw
        print("Port scan completed")

    @listen(perform_scan)
    def create_report(self):
        """Create a report based on the ip_address scan results"""
        print(f"Creating a report for {self.state.ip_address}")
        result = (
            SecurityToolsCrew()
            .crew()
            .kickoff(inputs={
                "ip_address": self.state.ip_address,
                "scan_results": self.state.scan_results
            })
        )
        # Save the report to a file
        with open("output/security_report.md", "w") as file:
            file.write(result.raw if hasattr(result, 'raw') else result)

        print("Report created")


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
