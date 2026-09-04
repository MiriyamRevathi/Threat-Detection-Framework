"""Performance Benchmark Runner Module"""
import time

class BenchmarkRunner:
    def __init__(self, iterations: int = 100):
        self.iterations = iterations

    def run_benchmark(self, func, *args, **kwargs) -> float:
        start = time.time()
        for _ in range(self.iterations):
            func(*args, **kwargs)
        return round(time.time() - start, 4)
