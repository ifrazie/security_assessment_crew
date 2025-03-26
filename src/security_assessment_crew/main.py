#!/usr/bin/env python
from pydantic import BaseModel
from crewai.flow import Flow, listen, start
from security_assessment_crew.crews.recon_crew.recon_crew import SecurityToolsCrew


class ScanState(BaseModel):
    ip_address: str = "127.0.0.1"
    scan_results: str = ""


class SecurityScanFlow(Flow[ScanState]):
    
    @start()
    def initialize_scan(self):
        print("Initializing security scan")
        # You could set a different default IP here if needed
        self.state.ip_address = "192.168.4.29"

    @listen(initialize_scan)
    def perform_scan(self):
        print(f"Scanning IP: {self.state.ip_address}")
        result = (
            SecurityToolsCrew()
            .crew()
            .kickoff(inputs={"ip_address": self.state.ip_address})
        )
        print("Scan completed")
        self.state.scan_results = result.raw

    @listen(perform_scan)
    def save_results(self):
        print("Saving scan results")
        with open("scan_results.txt", "w", encoding='utf-8') as f:
            f.write(self.state.scan_results)


def kickoff():
    security_flow = SecurityScanFlow()
    security_flow.kickoff()


def plot():
    security_flow = SecurityScanFlow()
    security_flow.plot()


if __name__ == "__main__":
    kickoff()
