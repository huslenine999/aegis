"""Bounded data-only Redis requests to services that hold credentials.

Privileged consumers never read RQ jobs, pickle data, import paths, or callbacks.
Each entrypoint supplies its own fixed operation-to-handler mapping.
"""

import json
import logging
import math
import re
import signal
import time
from contextlib import contextmanager
from typing import Any, Callable
from uuid import uuid4

from redis import Redis


LOGGER = logging.getLogger("aegis.services")
SERVICES = {"evidence-signing", "github-credentials", "notifications"}
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_PENDING_REQUESTS = 1000
MAX_REQUEST_SECONDS = 86400
MAX_HANDLER_SECONDS = 60
HEARTBEAT_SECONDS = 90
RESPONSE_SECONDS = 60
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")

# Capacity checking and insertion must be atomic across concurrent producers.
ENQUEUE_SCRIPT = """
if redis.call('LLEN', KEYS[1]) >= tonumber(ARGV[3]) then return 0 end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[4])
redis.call('RPUSH', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
"""
TAKE_SCRIPT = """
if redis.call('STRLEN', KEYS[1]) > tonumber(ARGV[1]) then
    redis.call('DEL', KEYS[1])
    return false
end
local value = redis.call('GET', KEYS[1])
redis.call('DEL', KEYS[1])
return value
"""


class ServiceRefused(RuntimeError):
    """A service declined a request, failed, or did not answer in time."""


class _HandlerTimeout(BaseException):
    # Delivery code catches ordinary exceptions; it must not swallow deadlines.
    pass


def service_key(service: str, kind: str, request_id: str | None = None) -> str:
    if service not in SERVICES or kind not in {"queue", "request", "response", "heartbeat"}:
        raise ServiceRefused("Unknown service channel.")
    if kind in {"request", "response"}:
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise ServiceRefused("Invalid service request identifier.")
        return f"aegis:service:v1:{service}:{kind}:{request_id}"
    return f"aegis:service:v1:{service}:{kind}"


def service_connection():
    from .database import REDIS_URL

    return Redis.from_url(
        REDIS_URL,
        socket_connect_timeout=5, socket_timeout=5,
    )


def _bounded_depth(value: Any, remaining: int = 32) -> bool:
    if remaining < 0:
        return False
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    return all(_bounded_depth(child, remaining - 1) for child in children)


def _encode(value: Any) -> bytes:
    try:
        raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ServiceRefused("Service messages must contain JSON data.") from exc
    if len(raw) > MAX_MESSAGE_BYTES or not _bounded_depth(value):
        raise ServiceRefused("Service message exceeds its size or nesting limit.")
    return raw


def _decode(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES:
        raise ServiceRefused("Invalid service message size.")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ServiceRefused("Invalid service JSON.") from exc
    if not isinstance(value, dict) or not _bounded_depth(value):
        raise ServiceRefused("Service messages must be bounded JSON objects.")
    return value


def _request(raw: bytes) -> dict:
    envelope = _decode(raw)
    if set(envelope) != {"operation", "payload", "deadline", "reply"}:
        raise ServiceRefused("Malformed service request.")
    deadline = envelope["deadline"]
    now = time.time()
    if (
        not isinstance(envelope["operation"], str)
        or not isinstance(envelope["payload"], dict)
        or not isinstance(envelope["reply"], bool)
        or isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not now < deadline <= now + MAX_REQUEST_SECONDS
    ):
        raise ServiceRefused("Invalid or expired service request.")
    _encode(envelope)
    return envelope


@contextmanager
def _deadline(seconds: float):
    previous = signal.getsignal(signal.SIGALRM)

    def expire(_signum, _frame):
        raise _HandlerTimeout()

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def dispatch_request(raw: bytes, handlers: dict[str, Callable[[dict], Any]]) -> dict:
    """Dispatch only a statically registered operation, within its deadline."""
    try:
        envelope = _request(raw)
        handler = handlers.get(envelope["operation"])
        if handler is None:
            raise ServiceRefused("Unknown service operation.")
        with _deadline(min(MAX_HANDLER_SECONDS, envelope["deadline"] - time.time())):
            result = handler(envelope["payload"])
        response = {"ok": True, "data": result}
        _encode(response)
        return response
    except (_HandlerTimeout, Exception):
        LOGGER.warning("Service request refused or failed", exc_info=True)
        return {"ok": False}


def enqueue_service(
    service: str, operation: str, payload: dict, *, timeout: float = 300,
    reply: bool = False, connection=None,
) -> str:
    if (
        not isinstance(operation, str) or not isinstance(payload, dict)
        or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
        or not 0 < timeout <= MAX_REQUEST_SECONDS
        or not isinstance(reply, bool)
    ):
        raise ServiceRefused("Invalid service request.")
    request_id = uuid4().hex
    queue = service_key(service, "queue")
    key = service_key(service, "request", request_id)
    raw = _encode({"operation": operation, "payload": payload, "deadline": time.time() + timeout, "reply": reply})
    client = connection if connection is not None else service_connection()
    try:
        accepted = client.eval(ENQUEUE_SCRIPT, 2, queue, key, request_id, raw, MAX_PENDING_REQUESTS, math.ceil(timeout), MAX_REQUEST_SECONDS)
    except Exception as exc:
        raise ServiceRefused("Service queue is unavailable.") from exc
    if not accepted:
        raise ServiceRefused("Service queue is full.")
    return request_id


def call_service(
    service: str, operation: str, request: dict, *, label: str, timeout: float,
    error: type[ServiceRefused] = ServiceRefused,
) -> Any:
    client = service_connection()
    try:
        request_id = enqueue_service(service, operation, request, timeout=timeout, reply=True, connection=client)
    except Exception as exc:
        raise error(f"The {label} queue is unavailable.") from exc
    request_key = service_key(service, "request", request_id)
    response_key = service_key(service, "response", request_id)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            raw = client.getrange(response_key, 0, MAX_MESSAGE_BYTES)
            if raw:
                response = _decode(raw)
                if set(response) != {"ok", "data"} or response["ok"] is not True:
                    raise error(f"The {label} refused or failed the request.")
                return response["data"]
            time.sleep(0.05)
        raise error(f"The {label} did not respond in time.")
    except error:
        raise
    except Exception as exc:
        raise error(f"The {label} refused or failed the request.") from exc
    finally:
        try:
            client.delete(request_key, response_key)
        except Exception:
            LOGGER.warning("Service response cleanup failed; keys will expire", exc_info=True)


def _record_failure(service: str) -> None:
    if service == "notifications":
        from .observability import record_notification_failure

        record_notification_failure()


def process_request(connection, service: str, request_id: str, handlers: dict[str, Callable[[dict], Any]]) -> None:
    key = service_key(service, "request", request_id)
    raw = connection.eval(TAKE_SCRIPT, 1, key, MAX_MESSAGE_BYTES)
    if not raw:
        LOGGER.warning("Service request expired or exceeded its size limit", extra={"service": service})
        _record_failure(service)
        return
    try:
        envelope = _request(raw)
    except ServiceRefused:
        LOGGER.warning("Discarded malformed or expired service request")
        _record_failure(service)
        return
    response = dispatch_request(raw, handlers)
    if not response["ok"]:
        _record_failure(service)
    if envelope["reply"]:
        connection.set(service_key(service, "response", request_id), _encode(response), ex=RESPONSE_SECONDS)


def service_available(service: str, connection=None) -> bool:
    client = connection if connection is not None else service_connection()
    return bool(client.get(service_key(service, "heartbeat")))


def serve_service(service: str, handlers: dict[str, Callable[[dict], Any]]) -> None:
    """Run a fixed-handler consumer; legacy executable RQ queues are untouched."""
    queue = service_key(service, "queue")
    connection = service_connection()
    while True:
        connection.set(service_key(service, "heartbeat"), b"1", ex=HEARTBEAT_SECONDS)
        item = connection.blpop(queue, timeout=1)
        if item is None:
            continue
        try:
            request_id = item[1].decode("ascii")
            process_request(connection, service, request_id, handlers)
        except (ServiceRefused, UnicodeError):
            LOGGER.warning("Discarded invalid service request identifier")
