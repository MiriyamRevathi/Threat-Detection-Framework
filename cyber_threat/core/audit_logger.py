"""Security Audit Logger Module"""
import time
import json
import os

class SecurityAuditLogger:
    def __init__(self, log_path: str = "audit.log"):
        self.log_path = log_path

    def log_event(self, event_type: str, user: str, details: dict):
        payload = {
            "timestamp": time.time(),
            "event_type": event_type,
            "user": user,
            "details": details
        }
        return payload
