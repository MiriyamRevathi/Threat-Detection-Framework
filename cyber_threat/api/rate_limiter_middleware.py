"""Rate Limiter Middleware Module"""
import time

class RateLimiterMiddleware:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.clients = {}

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        requests = self.clients.get(client_ip, [])
        requests = [r for r in requests if r > now - self.window_seconds]
        if len(requests) < self.max_requests:
            requests.append(now)
            self.clients[client_ip] = requests
            return True
        return False
