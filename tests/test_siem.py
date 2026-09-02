import pytest

def test_cef_format():
    log_entry = "CEF:0|AXAT|SentinelX|2.0|100|Threat Detected|8|src=192.168.1.1 dst=10.0.0.1"
    assert log_entry.startswith("CEF:0")

def test_leef_format():
    log_entry = "LEEF:2.0|AXAT|SentinelX|2.0|ThreatDetected|devTimeFormat=yyyy-MM-dd"
    assert log_entry.startswith("LEEF:2.0")
