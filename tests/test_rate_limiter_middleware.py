import pytest
from cyber_threat.api.rate_limiter_middleware import RateLimiterMiddleware

def test_rate_limiter():
    limiter = RateLimiterMiddleware(max_requests=2, window_seconds=60)
    assert limiter.is_allowed("192.168.1.100") is True
    assert limiter.is_allowed("192.168.1.100") is True
    assert limiter.is_allowed("192.168.1.100") is False
