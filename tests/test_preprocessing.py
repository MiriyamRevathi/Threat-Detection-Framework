import pytest
import pandas as pd

def test_feature_normalization():
    df = pd.DataFrame({'a': [1, 2, 3], 'b': [10, 20, 30]})
    normalized = (df - df.min()) / (df.max() - df.min())
    assert normalized['a'].min() == 0.0
    assert normalized['a'].max() == 1.0

def test_target_column_stripping():
    df = pd.DataFrame({'a': [1, 2], 'Attack Type': ['Normal', 'DoS']})
    if 'Attack Type' in df.columns:
        df = df.drop(columns=['Attack Type'])
    assert 'Attack Type' not in df.columns
