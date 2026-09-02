import pytest
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from predict import predict_attacks

def test_predict_attacks_valid():
    sample_file = os.path.join(os.path.dirname(__file__), '..', 'sample_data', 'sample_dataset1.csv')
    if os.path.exists(sample_file):
        result = predict_attacks(sample_file)
        assert isinstance(result, dict)
        assert "total_records" in result
        assert "normal_records" in result
        assert "threat_records" in result
        assert "risk_level" in result
        assert result["total_records"] > 0
