import hashlib
import hmac
import ipaddress
import json
import logging
import os
import smtplib
import socket
import ssl
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlparse

import urllib3
from cryptography.fernet import Fernet

from .database import get_connection
from .resource_budgets import ResourceLimitError
from .observability import record_notification_failure


CHANNEL_TYPES = {"webhook", "slack", "teams", "email"}
EVENT_TYPES = {"completed", "blocked", "failed", "cancelled"}
LOGGER = logging.getLogger("aegis.notifications")
MAX_WEBHOOK_RESPONSE_BYTES = 64 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fernet() -> Fernet:
    return Fernet(os.environ["AEGIS_ENCRYPTION_KEY"].encode())


def _encrypt(value: dict) -> str:
    return _fernet().encrypt(json.dumps(value, separators=(",", ":")).encode()).decode()


def _decrypt(value: str) -> dict:
    return json.loads(_fernet().decrypt(value.encode()))


def _resolve_webhook_url(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook URLs must use HTTPS.")
    resolved = set()
    for address in socket.getaddrinfo(parsed.hostname, parsed.port or 443):
        ip = ipaddress.ip_address(address[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or not ip.is_global
        ):
            raise ValueError("Webhook URL resolves to a non-public address.")
        resolved.add(str(ip))
    if not resolved:
        raise ValueError("Webhook URL did not resolve to a public address.")
    return parsed, sorted(resolved)


def _validate_webhook_url(url: str) -> None:
    _resolve_webhook_url(url)


def _post_pinned(url: str, **kwargs):
    parsed, addresses = _resolve_webhook_url(url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    headers = dict(kwargs.get("headers") or {})
    headers["Host"] = hostname if port == 443 else f"{hostname}:{port}"
    body: bytes | None
    if "json" in kwargs:
        body = json.dumps(kwargs["json"], separators=(",", ":")).encode()
        headers.setdefault("Content-Type", "application/json")
    else:
        raw_body = kwargs.get("data")
        if isinstance(raw_body, bytes):
            body = raw_body
        elif isinstance(raw_body, str):
            body = raw_body.encode()
        elif raw_body is None:
            body = None
        else:
            raise TypeError("Webhook body must be bytes or text.")
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    pool = urllib3.HTTPSConnectionPool(
        addresses[0],
        port=port,
        assert_hostname=hostname,
        server_hostname=hostname,
        cert_reqs="CERT_REQUIRED",
        timeout=urllib3.Timeout(connect=5, read=10),
        retries=False,
        maxsize=1,
        block=True,
    )
    try:
        response = pool.urlopen(
            "POST",
            target,
            body=body,
            headers=headers,
            redirect=False,
            retries=False,
            preload_content=False,
        )
        try:
            response_body = response.read(MAX_WEBHOOK_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_WEBHOOK_RESPONSE_BYTES:
                raise ResourceLimitError("Webhook response exceeds the configured limit.")
            return response
        finally:
            response.close()
    finally:
        pool.close()


def _post_with_retries(url: str, **kwargs):
    last_error = None
    for attempt in range(3):
        try:
            response = _post_pinned(url, **kwargs)
            status_code = int(
                getattr(response, "status_code", getattr(response, "status", 200))
            )
            if 300 <= status_code < 400:
                raise RuntimeError("Webhook redirects are not allowed.")
            if status_code >= 400:
                raise RuntimeError(f"Webhook returned HTTP {status_code}.")
            return response
        except (urllib3.exceptions.HTTPError, OSError, RuntimeError, ValueError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(0.25 * (2**attempt))
    raise RuntimeError(f"Webhook delivery failed after retries: {last_error}")


def create_channel(
    *,
    project_id: int,
    name: str,
    channel_type: str,
    config: dict,
    events: list[str],
    created_by: int,
) -> int:
    if not name:
        raise ValueError("Notification name is required.")
    if channel_type not in CHANNEL_TYPES:
        raise ValueError("Unsupported notification channel.")
    normalized_events = sorted(set(events))
    if not normalized_events or not set(normalized_events) <= EVENT_TYPES:
        raise ValueError("Invalid notification events.")
    if channel_type in {"webhook", "slack", "teams"}:
        _validate_webhook_url(str(config.get("url", "")))
    elif channel_type == "email" and "@" not in str(config.get("to", "")):
        raise ValueError("A valid notification email is required.")
    with get_connection() as connection:
        cursor = connection.execute(
            """INSERT INTO notification_channels
               (project_id, name, channel_type, config_encrypted, events,
                enabled, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
            (
                project_id,
                name,
                channel_type,
                _encrypt(config),
                ",".join(normalized_events),
                created_by,
                _now(),
            ),
        )
        channel_id = getattr(cursor, "lastrowid", None)
        if channel_id is None:
            channel_id = connection.execute(
                """SELECT id FROM notification_channels
                   WHERE project_id = ? AND created_by = ?
                   ORDER BY id DESC LIMIT 1""",
                (project_id, created_by),
            ).fetchone()[0]
    return int(channel_id)


def list_channels(project_id: int) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, name, channel_type, events, enabled, created_at
               FROM notification_channels WHERE project_id = ? ORDER BY id""",
            (project_id,),
        ).fetchall()
    return [
        {
            "id": int(row[0]),
            "name": row[1],
            "channel_type": row[2],
            "events": row[3].split(","),
            "enabled": bool(row[4]),
            "created_at": row[5],
        }
        for row in rows
    ]


def delete_channel(channel_id: int, project_id: int) -> bool:
    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM notification_channels WHERE id = ? AND project_id = ?",
            (channel_id, project_id),
        )
    return bool(getattr(cursor, "rowcount", 0))


def _record_delivery(channel_id: int, event: str, status: str, error: str = "") -> None:
    with get_connection() as connection:
        connection.execute(
            """INSERT INTO notification_deliveries
               (channel_id, event_type, status, error, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (channel_id, event, status, error[:1000] or None, _now()),
        )


def _deliver(channel_type: str, config: dict, event: str, payload: dict) -> None:
    title = f"Aegis scan {event}: {payload.get('project_name', 'project')}"
    text = f"{title}. Job {payload.get('job_id', 'unknown')}. New findings: {payload.get('new_findings', 0)}."
    if channel_type in {"webhook", "slack", "teams"}:
        url = str(config["url"])
        _validate_webhook_url(url)
        if channel_type == "webhook":
            body = json.dumps({"event": event, "data": payload}, separators=(",", ":")).encode()
            headers = {"Content-Type": "application/json", "X-Aegis-Event": event}
            if config.get("secret"):
                headers["X-Aegis-Signature-256"] = "sha256=" + hmac.new(
                    str(config["secret"]).encode(), body, hashlib.sha256
                ).hexdigest()
            _post_with_retries(url, data=body, headers=headers)
        else:
            _post_with_retries(url, json={"text": text})
        return
    message = EmailMessage()
    message["Subject"] = title
    message["From"] = os.environ["AEGIS_SMTP_FROM"]
    destination = str(config["to"])
    if "\n" in destination or "\r" in destination:
        raise ValueError("Invalid email destination.")
    message["To"] = destination
    message.set_content(text)
    host = os.environ["AEGIS_SMTP_HOST"]
    port = int(os.environ.get("AEGIS_SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        username = os.environ.get("AEGIS_SMTP_USERNAME")
        if username:
            smtp.login(username, os.environ.get("AEGIS_SMTP_PASSWORD", ""))
        smtp.send_message(message)


def send_project_notification(project_id: int, event: str, payload: dict) -> None:
    if event not in EVENT_TYPES:
        return
    try:
        with get_connection() as connection:
            rows = connection.execute(
                """SELECT id, channel_type, config_encrypted, events
                   FROM notification_channels
                   WHERE project_id = ? AND enabled = 1""",
                (project_id,),
            ).fetchall()
    except Exception:
        record_notification_failure()
        return
    for row in rows:
        if event not in row[3].split(","):
            continue
        try:
            _deliver(row[1], _decrypt(row[2]), event, payload)
            try:
                _record_delivery(int(row[0]), event, "delivered")
            except Exception:
                pass
        except Exception as exc:
            record_notification_failure()
            try:
                _record_delivery(int(row[0]), event, "failed", str(exc))
            except Exception:
                pass


def queue_project_notification(project_id: int, event: str, payload: dict) -> bool:
    """Hand notification delivery to a credential-bearing notifier process."""
    require_notifier = os.environ.get("AEGIS_REQUIRE_NOTIFIER", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not require_notifier:
        send_project_notification(project_id, event, payload)
        return True
    try:
        from redis import Redis
        from rq import Queue

        queue = Queue(
            "notifications",
            connection=Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0")),
        )
        queue.enqueue(
            send_project_notification,
            project_id,
            event,
            payload,
            job_timeout=60,
            result_ttl=300,
            failure_ttl=86400,
        )
        return True
    except Exception:
        record_notification_failure()
        LOGGER.exception(
            "Failed to enqueue notification",
            extra={"project_id": project_id, "event": event},
        )
        return False


def test_channel(channel_id: int, project_id: int) -> None:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT channel_type, config_encrypted FROM notification_channels
               WHERE id = ? AND project_id = ?""",
            (channel_id, project_id),
        ).fetchone()
    if not row:
        raise ValueError("Notification channel not found.")
    _deliver(row[0], _decrypt(row[1]), "completed", {"project_name": "Test notification", "job_id": "test"})


def queue_test_channel(channel_id: int, project_id: int) -> bool:
    require_notifier = os.environ.get("AEGIS_REQUIRE_NOTIFIER", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not require_notifier:
        test_channel(channel_id, project_id)
        return True
    try:
        from redis import Redis
        from rq import Queue

        Queue(
            "notifications",
            connection=Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0")),
        ).enqueue(
            test_channel,
            channel_id,
            project_id,
            job_timeout=60,
            result_ttl=300,
            failure_ttl=86400,
        )
        return True
    except Exception:
        record_notification_failure()
        LOGGER.exception(
            "Failed to enqueue test notification",
            extra={"project_id": project_id, "channel_id": channel_id},
        )
        return False
