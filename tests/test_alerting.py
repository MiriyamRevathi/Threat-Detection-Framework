import pytest

def test_alert_threshold():
    threat_score = 25.5
    alert_level = "CRITICAL" if threat_score > 20 else "INFO"
    assert alert_level == "CRITICAL"

def test_incident_aggregation():
    alerts = [{"id": 1, "type": "DoS"}, {"id": 2, "type": "PortScan"}]
    assert len(alerts) == 2
