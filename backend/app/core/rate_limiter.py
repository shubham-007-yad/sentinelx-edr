import time
from typing import Callable
from fastapi import Request, HTTPException, status
import redis

from app.core.config import settings
from app.core.logging import logger

def get_redis_client() -> redis.Redis:
    return redis.Redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        socket_timeout=3,
        socket_connect_timeout=3
    )

class RateLimiter:
    """
    Sliding window per-minute rate limiter backed by Redis.
    Attaches to FastAPI endpoints as a dependency.
    """
    def __init__(self, requests_per_minute: int = 60, scope: str = "global"):
        self.requests_per_minute = requests_per_minute
        self.scope = scope

    def __call__(self, request: Request):
        # Identify client by IP address or Bearer token hash
        client_ip = request.client.host if request.client else "unknown"
        forwarded_ip = request.headers.get("x-forwarded-for")
        if forwarded_ip:
            client_ip = forwarded_ip.split(",")[0].strip()

        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            identifier = f"token_{hash(auth_header)}"
        else:
            identifier = f"ip_{client_ip}"

        current_window = int(time.time() // 60)
        key = f"sentinelx:ratelimit:{self.scope}:{identifier}:{current_window}"

        try:
            r_client = get_redis_client()
            count = r_client.incr(key)
            if count == 1:
                r_client.expire(key, 65)  # Expire key slightly after window ends

            if count > self.requests_per_minute:
                retry_after = 60 - int(time.time() % 60)
                logger.warning(
                    f"[RateLimiter] Limit exceeded for '{identifier}' on {request.url.path} "
                    f"({count}/{self.requests_per_minute} req/min)"
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for scope '{self.scope}'. Maximum {self.requests_per_minute} requests per minute allowed.",
                    headers={"Retry-After": str(retry_after)}
                )
        except redis.RedisError as e:
            # Fallback gracefully if Redis is temporarily unreachable
            logger.warning(f"[RateLimiter] Redis connection error during rate limiting check: {e}")
            pass

# Pre-configured rate limiting dependencies
rate_limit_auth = RateLimiter(requests_per_minute=10, scope="auth_login")
rate_limit_register = RateLimiter(requests_per_minute=5, scope="auth_register")
rate_limit_telemetry = RateLimiter(requests_per_minute=120, scope="telemetry_ingest")
rate_limit_commands = RateLimiter(requests_per_minute=30, scope="agent_commands")
rate_limit_general = RateLimiter(requests_per_minute=300, scope="api_general")
