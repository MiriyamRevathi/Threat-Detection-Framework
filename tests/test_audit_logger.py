import pytest
from cyber_threat.core.audit_logger import SecurityAuditLogger

def test_audit_logger_event():
    logger = SecurityAuditLogger()
    event = logger.log_event("LOGIN", "admin", {"ip": "127.0.0.1"})
    assert event["event_type"] == "LOGIN"
    assert event["user"] == "admin"
