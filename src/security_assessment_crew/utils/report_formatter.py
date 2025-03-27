from typing import List
from security_assessment_crew.models import PortInfo, Recommendation, ReportOutline, ScanOverview

class SecurityReportFormatter:
    @staticmethod
    def format_report(report: ReportOutline) -> str:
        """Convert report object to markdown format"""
        sections = [
            f"# {report.title}\n",
            SecurityReportFormatter._format_overview(report.scan_overview),
            SecurityReportFormatter._format_ports(report.port_findings),
            SecurityReportFormatter._format_recommendations(report.recommendations),
            "## Conclusion\n" + report.conclusion + "\n",
            "---\n"
        ]
        return "\n".join(sections)

    @staticmethod
    def _format_overview(overview: ScanOverview) -> str:
        return (
            "## Scan Overview\n"
            f"- **Status:** {overview.status}\n"
            f"- **Total Ports Scanned:** {overview.total_ports_scanned}\n"
            f"- **Scan Duration:** {overview.scan_duration}\n"
        )

    @staticmethod
    def _format_ports(ports: List[PortInfo]) -> str:
        sections = ["## Open Ports and Associated Risks\n"]
        for port in ports:
            sections.append(
                f"### Port {port.port_number} ({port.service_name})\n"
                f"- **State:** {port.state}\n"
                f"- **Risk Level:** {port.risk_level}\n"
                f"- **Description:** {port.description}\n"
            )
        return "\n".join(sections)

    @staticmethod
    def _format_recommendations(recs: List[Recommendation]) -> str:
        sections = ["## Recommendations\n"]
        for rec in recs:
            sections.append(f"- {rec.details}\n")
        return "\n".join(sections)
