import pytest
from cyber_threat.visualization.report_writer import ReportWriterExporter

def test_report_writer():
    writer = ReportWriterExporter(format_type="json")
    out = writer.export_summary({"risk_level": "HIGH", "score": 98.5})
    assert '"risk_level": "HIGH"' in out
