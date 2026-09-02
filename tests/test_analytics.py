import pytest

def test_mitre_mapping():
    mitre_map = {"DoS": "T1498", "PortScan": "T1046", "BruteForce": "T1110"}
    assert mitre_map["DoS"] == "T1498"
    assert mitre_map["PortScan"] == "T1046"

def test_time_series_anomaly():
    traffic_rate = [100, 105, 98, 102, 5000, 101]
    mean = sum(traffic_rate) / len(traffic_rate)
    anomalies = [x for x in traffic_rate if x > mean * 3]
    assert len(anomalies) == 1
    assert anomalies[0] == 5000
