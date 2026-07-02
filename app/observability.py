import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import Counter, deque


LOGGER = logging.getLogger("aegis.http")
_lock = threading.Lock()
_requests = Counter()
_latency_sum = Counter()
_recent_requests = deque(maxlen=500)


def configure_logging() -> None:
    level = getattr(logging, os.environ.get("AEGIS_LOG_LEVEL", "INFO").upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.handlers.clear()
    LOGGER.addHandler(handler)
    LOGGER.setLevel(level)
    LOGGER.propagate = False


class ObservabilityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = 500
        request_id = dict(scope.get("headers", [])).get(b"x-request-id", b"").decode()
        request_id = request_id[:128] or uuid.uuid4().hex

        async def observed_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
        finally:
            elapsed = time.perf_counter() - started
            path = scope.get("path", "unknown")
            method = scope.get("method", "GET")
            status_class = f"{status // 100}xx"
            with _lock:
                _requests[(method, path, status_class)] += 1
                _latency_sum[(method, path)] += elapsed
            event = {
                "event": "http_request",
                "request_id": request_id,
                "method": method,
                "path": path,
                "status": status,
                "duration_ms": round(elapsed * 1000, 2),
                "client": scope.get("client", ["unknown"])[0],
            }
            with _lock:
                _recent_requests.appendleft(event)
            LOGGER.info(json.dumps(event, separators=(",", ":")))


def render_metrics() -> str:
    lines = [
        "# HELP aegis_http_requests_total HTTP requests handled.",
        "# TYPE aegis_http_requests_total counter",
    ]
    with _lock:
        for (method, path, status_class), value in sorted(_requests.items()):
            labels = f'method="{method}",path="{path}",status_class="{status_class}"'
            lines.append(f"aegis_http_requests_total{{{labels}}} {value}")
        lines.extend(
            [
                "# HELP aegis_http_request_duration_seconds_sum Total request duration.",
                "# TYPE aegis_http_request_duration_seconds_sum counter",
            ]
        )
        for (method, path), value in sorted(_latency_sum.items()):
            labels = f'method="{method}",path="{path}"'
            lines.append(f"aegis_http_request_duration_seconds_sum{{{labels}}} {value:.6f}")
    return "\n".join(lines) + "\n"


def recent_requests(limit: int = 100) -> list[dict]:
    with _lock:
        return list(_recent_requests)[: max(1, min(limit, 500))]
