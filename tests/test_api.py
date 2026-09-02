import pytest

def test_api_status_code():
    status = {"status": "ok", "version": "2.0.0"}
    assert status["status"] == "ok"
    assert status["version"] == "2.0.0"
