"""Report Writer Exporter Module"""
import json

class ReportWriterExporter:
    def __init__(self, format_type: str = "json"):
        self.format_type = format_type

    def export_summary(self, threat_data: dict) -> str:
        if self.format_type == "json":
            return json.dumps(threat_data, indent=2)
        return str(threat_data)
