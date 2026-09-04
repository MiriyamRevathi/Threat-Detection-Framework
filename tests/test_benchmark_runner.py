import pytest
from cyber_threat.utils.benchmark_runner import BenchmarkRunner

def test_benchmark_runner():
    runner = BenchmarkRunner(iterations=10)
    duration = runner.run_benchmark(lambda: sum(range(100)))
    assert duration >= 0.0
