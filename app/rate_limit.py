import json
import os
import time


SENSITIVE_PATHS = frozenset(
    {
        "/api/auth/login",
        "/api/setup",
        "/api/auth/oidc/start",
        "/api/auth/oidc/callback",
        "/api/github/connect",
        "/api/github/callback",
        "/api/github/disconnect",
    }
)


def route_class(path: str) -> str:
    """Map request paths to a finite set of rate-limit key classes."""

    if path in SENSITIVE_PATHS:
        return "sensitive"
    if path == "/run-scan":
        return "scan"
    if path.startswith("/api/auth/"):
        return "auth"
    if path.startswith("/api/github/"):
        return "github"
    if path.startswith("/api/projects/"):
        return "project"
    if path.startswith("/api/"):
        return "api"
    if path == "/static" or path.startswith("/static/"):
        return "static"
    return "other"


def _configured_limit(name: str, default: int) -> int:
    raw_value = os.environ.get(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive integer.") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be a positive integer.")
    return value


class RateLimitMiddleware:
    def __init__(self, app, redis_client):
        self.app = app
        self.redis = redis_client
        self.default_limit = _configured_limit("AEGIS_RATE_LIMIT_PER_MINUTE", 120)
        self.aggregate_limit = _configured_limit(
            "AEGIS_AGGREGATE_RATE_LIMIT_PER_MINUTE", 240
        )
        self.scan_limit = _configured_limit("AEGIS_SCAN_RATE_LIMIT_PER_MINUTE", 10)
        self.login_limit = _configured_limit("AEGIS_LOGIN_RATE_LIMIT_PER_MINUTE", 5)
        self.fail_closed = os.environ.get("AEGIS_ENV", "development").lower() == "production"

    def _limit(self, path: str) -> int:
        if path in SENSITIVE_PATHS:
            return self.login_limit
        if path == "/run-scan":
            return self.scan_limit
        return self.default_limit

    def _increment(self, key: str) -> int:
        count = int(self.redis.incr(key))
        if count == 1:
            self.redis.expire(key, 61)
        return count

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in {"/health", "/ready", "/metrics"}:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        address = client[0] if client else "unknown"
        path = scope.get("path", "")
        bucket = int(time.time() // 60)
        limit = self._limit(path)
        try:
            aggregate_count = self._increment(f"rate:client:{address}:{bucket}")
            route_count = self._increment(
                f"rate:route:{route_class(path)}:{address}:{bucket}"
            )
        except Exception:
            method = scope.get("method", "GET").upper()
            if self.fail_closed and (
                method not in {"GET", "HEAD", "OPTIONS"}
                or path in SENSITIVE_PATHS
            ):
                await self._unavailable(send)
                return
            aggregate_count = route_count = 1
        if aggregate_count > self.aggregate_limit or route_count > limit:
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

    @staticmethod
    async def _unavailable(send):
        body = json.dumps({"detail": "Rate limiting is temporarily unavailable."}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", b"5"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def allow_websocket(redis_client, address: str, limit: int = 20) -> bool:
    bucket = int(time.time() // 60)
    key = f"rate:websocket:{address}:{bucket}"
    try:
        count = int(redis_client.incr(key))
        if count == 1:
            redis_client.expire(key, 61)
        return count <= limit
    except Exception:
        return os.environ.get("AEGIS_ENV", "development").lower() != "production"
