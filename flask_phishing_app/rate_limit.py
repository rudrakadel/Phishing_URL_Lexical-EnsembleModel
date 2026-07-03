from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


@dataclass(slots=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_in_seconds: int


class RateLimiter:
    def __init__(self, window_seconds: int, redis_url: str = "") -> None:
        self.window_seconds = window_seconds
        self._lock = Lock()
        self._memory: dict[str, tuple[int, int]] = {}
        self._redis = None
        if redis and redis_url:
            try:
                client = redis.Redis.from_url(redis_url, decode_responses=True)
                client.ping()
                self._redis = client
            except Exception:
                self._redis = None

    def check(self, bucket: str, limit: int) -> RateLimitResult:
        now = int(time.time())
        window_start = now - (now % self.window_seconds)
        reset_in = max(1, (window_start + self.window_seconds) - now)
        if self._redis is not None:
            return self._check_redis(bucket, limit, window_start, reset_in)
        return self._check_memory(bucket, limit, window_start, reset_in)

    def _check_memory(self, bucket: str, limit: int, window_start: int, reset_in: int) -> RateLimitResult:
        with self._lock:
            count, current_window = self._memory.get(bucket, (0, window_start))
            if current_window != window_start:
                count = 0
                current_window = window_start
            count += 1
            self._memory[bucket] = (count, current_window)
            remaining = max(0, limit - count)
            return RateLimitResult(allowed=count <= limit, remaining=remaining, reset_in_seconds=reset_in)

    def _check_redis(self, bucket: str, limit: int, window_start: int, reset_in: int) -> RateLimitResult:
        assert self._redis is not None
        key = f"rate-limit:{bucket}:{window_start}"
        try:
            count = int(self._redis.incr(key))
            if count == 1:
                self._redis.expire(key, self.window_seconds)
            remaining = max(0, limit - count)
            return RateLimitResult(allowed=count <= limit, remaining=remaining, reset_in_seconds=reset_in)
        except Exception:
            return self._check_memory(bucket, limit, window_start, reset_in)
