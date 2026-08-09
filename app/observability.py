import json
import math
import logging
import os
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any


LOGGER = logging.getLogger("aegis.http")
_lock = threading.Lock()
_requests: defaultdict[tuple[str, str, str], int] = defaultdict(int)
_latency_sum: defaultdict[tuple[str, str], float] = defaultdict(float)
_latency_count: defaultdict[tuple[str, str], int] = defaultdict(int)
_latency_buckets: defaultdict[tuple[str, str, float], int] = defaultdict(int)
_recent_requests: deque[dict[str, Any]] = deque(maxlen=500)
_active_requests = 0
LATENCY_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
_SHARED_METRICS_KEY = "aegis:metrics"
_OPERATIONAL_METRICS = {
    "aegis_scan_queue_age_seconds": (
        "gauge",
        "Age of the most recently claimed scan job.",
    ),
    "aegis_worker_failures_total": (
        "counter",
        "Scan jobs that ended with a worker failure.",
    ),
    "aegis_notification_failures_total": (
        "counter",
        "Notification deliveries or enqueue operations that failed.",
    ),
    "aegis_audit_integrity_failures_total": (
        "counter",
        "Audit-chain verification failures.",
    ),
    "aegis_artifact_integrity_failures_total": (
        "counter",
        "Artifact integrity verification failures.",
    ),
}
_operational_metrics: dict[str, float] = {
    name: 0.0 for name in _OPERATIONAL_METRICS
}


def _shared_redis():
    """Resolve Redis lazily so observability remains import-safe in every process."""
    try:
        from .database import redis_client

        return redis_client
    except Exception:
        return None


def _set_shared_metric(name: str, value: float) -> None:
    client = _shared_redis()
    if client is None:
        return
    try:
        client.hset(_SHARED_METRICS_KEY, name, f"{value:.6f}")
    except Exception:
        LOGGER.debug("Unable to persist operational metric", exc_info=True)


def _increment_shared_metric(name: str) -> None:
    client = _shared_redis()
    if client is None:
        return
    try:
        increment = getattr(client, "hincrby", None)
        if callable(increment):
            increment(_SHARED_METRICS_KEY, name, 1)
            return
        current = client.hget(_SHARED_METRICS_KEY, name)
        current_value = float(current.decode() if isinstance(current, bytes) else current or 0)
        client.hset(_SHARED_METRICS_KEY, name, str(int(current_value) + 1))
    except Exception:
        LOGGER.debug("Unable to persist operational metric", exc_info=True)


def _shared_metric_snapshot() -> dict[str, float]:
    client = _shared_redis()
    if client is None:
        return {}
    snapshot: dict[str, float] = {}
    try:
        for name in _OPERATIONAL_METRICS:
            value = client.hget(_SHARED_METRICS_KEY, name)
            if value is not None:
                snapshot[name] = float(
                    value.decode() if isinstance(value, bytes) else value
                )
    except (TypeError, ValueError, OSError):
        LOGGER.debug("Unable to read shared operational metrics", exc_info=True)
    except Exception:
        LOGGER.debug("Unable to read shared operational metrics", exc_info=True)
    return snapshot


def record_scan_queue_age(age_seconds: float) -> None:
    """Record the age observed when a worker claims a queued scan."""
    if not math.isfinite(age_seconds) or age_seconds < 0:
        return
    with _lock:
        _operational_metrics["aegis_scan_queue_age_seconds"] = age_seconds
    _set_shared_metric("aegis_scan_queue_age_seconds", age_seconds)


def _record_operational_failure(name: str) -> None:
    with _lock:
        _operational_metrics[name] += 1
    _increment_shared_metric(name)


def record_worker_failure() -> None:
    _record_operational_failure("aegis_worker_failures_total")


def record_notification_failure() -> None:
    _record_operational_failure("aegis_notification_failures_total")


def record_audit_integrity_failure() -> None:
    _record_operational_failure("aegis_audit_integrity_failures_total")


def record_artifact_integrity_failure() -> None:
    _record_operational_failure("aegis_artifact_integrity_failures_total")


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
        global _active_requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        with _lock:
            _active_requests += 1
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
                _latency_count[(method, path)] += 1
                for bucket in LATENCY_BUCKETS:
                    if elapsed <= bucket:
                        _latency_buckets[(method, path, bucket)] += 1
                _active_requests -= 1
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
    shared_metrics = _shared_metric_snapshot()
    lines = [
        "# HELP aegis_http_requests_total HTTP requests handled.",
        "# TYPE aegis_http_requests_total counter",
    ]
    with _lock:
        for (method, path, status_class), request_count in sorted(_requests.items()):
            labels = f'method="{method}",path="{path}",status_class="{status_class}"'
            lines.append(f"aegis_http_requests_total{{{labels}}} {request_count}")
        lines.extend(
            [
                "# HELP aegis_http_request_duration_seconds HTTP request duration.",
                "# TYPE aegis_http_request_duration_seconds histogram",
            ]
        )
        for (method, path), latency_total in sorted(_latency_sum.items()):
            labels = f'method="{method}",path="{path}"'
            lines.append(
                f"aegis_http_request_duration_seconds_sum{{{labels}}} {latency_total:.6f}"
            )
            lines.append(
                f"aegis_http_request_duration_seconds_count{{{labels}}} "
                f"{_latency_count[(method, path)]}"
            )
            for bucket in LATENCY_BUCKETS:
                bucket_labels = f'{labels},le="{bucket:g}"'
                lines.append(
                    "aegis_http_request_duration_seconds_bucket"
                    f"{{{bucket_labels}}} {_latency_buckets[(method, path, bucket)]}"
                )
            infinity_labels = f'{labels},le="+Inf"'
            lines.append(
                "aegis_http_request_duration_seconds_bucket"
                f"{{{infinity_labels}}} {_latency_count[(method, path)]}"
            )
        lines.extend(
            [
                "# HELP aegis_http_active_requests In-flight HTTP requests.",
                "# TYPE aegis_http_active_requests gauge",
                f"aegis_http_active_requests {_active_requests}",
            ]
        )
        operational_metrics = {
            name: shared_metrics.get(name, value)
            for name, value in _operational_metrics.items()
        }
    for name, (metric_type, help_text) in _OPERATIONAL_METRICS.items():
        lines.extend(
            [
                f"# HELP {name} {help_text}",
                f"# TYPE {name} {metric_type}",
                f"{name} {operational_metrics[name]:.6f}",
            ]
        )
    return "\n".join(lines) + "\n"


def recent_requests(limit: int = 100) -> list[dict]:
    with _lock:
        return list(_recent_requests)[: max(1, min(limit, 500))]
