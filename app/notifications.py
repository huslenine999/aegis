import hashlib
import hmac
import ipaddress
import json
import os
import smtplib
import socket
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlparse

import requests
from cryptography.fernet import Fernet

try:
    from database import get_connection
except ImportError:
    from .database import get_connection


CHANNEL_TYPES = {"webhook", "slack", "teams", "email"}
EVENT_TYPES = {"completed", "blocked", "failed", "cancelled"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fernet() -> Fernet:
    return Fernet(os.environ["AEGIS_ENCRYPTION_KEY"].encode())


def _encrypt(value: dict) -> str:
    return _fernet().encrypt(json.dumps(value, separators=(",", ":")).encode()).decode()


def _decrypt(value: str) -> dict:
    return json.loads(_fernet().decrypt(value.encode()))


def _validate_webhook_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Webhook URLs must use HTTPS.")
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        ):
            raise ValueError("Webhook URL resolves to a non-public address.")


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
            response = requests.post(url, data=body, headers=headers, timeout=10)
        else:
            response = requests.post(url, json={"text": text}, timeout=10)
        response.raise_for_status()
        return
    message = EmailMessage()
    message["Subject"] = title
    message["From"] = os.environ["AEGIS_SMTP_FROM"]
    message["To"] = config["to"]
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
            try:
                _record_delivery(int(row[0]), event, "failed", str(exc))
            except Exception:
                pass


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
