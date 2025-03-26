from crewai.tools import BaseTool
from typing import Type, Annotated
from pydantic import BaseModel, Field, field_validator
import nmap
import re

class ScanNetworkToolSchema(BaseModel):
    """Input for Scan Network Tool."""
    ip_address: Annotated[str, Field(description="IP address to scan (IPv4 format)")] 

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("IP address must be a string")
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(pattern, value):
            raise ValueError('Invalid IP address format')
        return value

class ScanNetworkTool(BaseTool):
    name: str = "Scan Network Tool"
    description: str = "A tool to scan an IP address using nmap. Example input: {'ip_address': '192.168.1.1'}"
    args_schema: Type[BaseModel] = ScanNetworkToolSchema

    def _run(self, ip_address: str) -> str:
        try:
            nm = nmap.PortScanner()
            nm.scan(ip_address, '1-1024', arguments='-sV --version-intensity 5')
            
            results = {
                "status": "completed",
                "target": ip_address,
                "scan_info": {
                    "total_ports_scanned": 1024,
                    "scan_duration_ms": nm.scanstats()['elapsed'],
                    "ports": []
                }
            }
            
            if ip_address in nm.all_hosts():
                for proto in nm[ip_address].all_protocols():
                    for port in nm[ip_address][proto].keys():
                        port_info = nm[ip_address][proto][port]
                        results["scan_info"]["ports"].append({
                            "port": port,
                            "state": port_info["state"],
                            "service": port_info.get("name", "unknown"),
                            "version": port_info.get("version", "unknown"),
                            "risk_level": "High" if port in [21, 23, 445, 3389] else "Low"
                        })
            
            # Convert results to formatted string
            return f"""Scan Results for {ip_address}:
Status: {results['status']}
Total Ports Scanned: {results['scan_info']['total_ports_scanned']}
Scan Duration: {results['scan_info']['scan_duration_ms']}ms

Open Ports:
{self._format_ports(results['scan_info']['ports'])}"""

        except Exception as e:
            return f"Error scanning {ip_address}: {str(e)}"

    def _format_ports(self, ports: list) -> str:
        if not ports:
            return "No open ports found."
        
        formatted_ports = []
        for port in ports:
            risk = "⚠️ HIGH RISK" if port['risk_level'] == "High" else "✓ Low Risk"
            formatted_ports.append(
                f"Port {port['port']} ({port['service']} {port['version']}): {port['state']} - {risk}"
            )
        return "\n".join(formatted_ports)