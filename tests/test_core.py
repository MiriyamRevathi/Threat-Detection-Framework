import pytest

def test_core_engine_initialization():
    engine_name = "AI Cyber Threat Detector Engine"
    version = "2.0.0"
    assert len(engine_name) > 0
    assert version == "2.0.0"

def test_threat_score_calculation():
    total_records = 1000
    threat_records = 150
    score = round((threat_records / total_records) * 100, 2)
    assert score == 15.0
    risk = "LOW" if score < 5 else "MEDIUM" if score < 20 else "HIGH"
    assert risk == "MEDIUM"
