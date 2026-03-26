import time
from collections import defaultdict
from threading import Lock
from fastapi import Request, HTTPException


class SlidingWindowLimiter:
    """In-memory sliding window rate limiter — no extra dependencies."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._store: dict = defaultdict(list)
        self._lock = Lock()

    def _get_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def __call__(self, request: Request):
        ip = self._get_ip(request)
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            self._store[ip] = [t for t in self._store[ip] if t > cutoff]
            if len(self._store[ip]) >= self.max_requests:
                retry_after = int(self._store[ip][0] + self.window_seconds - now) + 1
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded ({self.max_requests} req/{self.window_seconds}s). "
                           f"Retry in {retry_after}s.",
                    headers={"Retry-After": str(retry_after)},
                )
            self._store[ip].append(now)


# Shared limiter instances (FastAPI Depends-compatible)
analyze_limit = SlidingWindowLimiter(max_requests=30, window_seconds=60)
upload_limit = SlidingWindowLimiter(max_requests=10, window_seconds=60)
