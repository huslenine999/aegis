import json
import os
import time


class RateLimitMiddleware:
    def __init__(self, app, redis_client):
        self.app = app
        self.redis = redis_client
        self.default_limit = int(os.environ.get("AEGIS_RATE_LIMIT_PER_MINUTE", "120"))
        self.scan_limit = int(os.environ.get("AEGIS_SCAN_RATE_LIMIT_PER_MINUTE", "10"))
        self.login_limit = int(os.environ.get("AEGIS_LOGIN_RATE_LIMIT_PER_MINUTE", "5"))

    def _limit(self, path: str) -> int:
        if path in {"/api/auth/login", "/api/setup"}:
            return self.login_limit
        if path == "/run-scan":
            return self.scan_limit
        return self.default_limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in {"/health", "/ready", "/metrics"}:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        address = client[0] if client else "unknown"
        path = scope.get("path", "")
        bucket = int(time.time() // 60)
        key = f"rate:{path}:{address}:{bucket}"
        limit = self._limit(path)
        try:
            count = int(self.redis.incr(key))
            if count == 1:
                self.redis.expire(key, 61)
        except Exception:
            count = 1
        if count > limit:
            body = json.dumps({"detail": "Rate limit exceeded."}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"retry-after", b"60"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


def allow_websocket(redis_client, address: str, limit: int = 20) -> bool:
    bucket = int(time.time() // 60)
    key = f"rate:websocket:{address}:{bucket}"
    try:
        count = int(redis_client.incr(key))
        if count == 1:
            redis_client.expire(key, 61)
        return count <= limit
    except Exception:
        return True
