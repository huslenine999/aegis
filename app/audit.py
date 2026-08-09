import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone

from .database import get_connection
from .observability import record_audit_integrity_failure


LOGGER = logging.getLogger("aegis.audit")
GENESIS_HASH = "0" * 64


def _audit_key() -> bytes:
    value = os.environ.get("AEGIS_AUDIT_HMAC_KEY", "")
    if not value:
        value = "development-audit-key-not-for-production"
    return value.encode()


def _event_payload(event: dict) -> bytes:
    return json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _event_hash(previous_hash: str, event: dict) -> str:
    return hmac.new(
        _audit_key(), bytes.fromhex(previous_hash) + _event_payload(event), hashlib.sha256
    ).hexdigest()


def record_audit(
    actor_id,
    action: str,
    resource_type: str,
    resource_id=None,
    details=None,
    tenant_id: int | None = None,
):
    try:
        with get_connection() as connection:
            if tenant_id is None and actor_id is not None:
                row = connection.execute(
                    "SELECT tenant_id FROM auth_users WHERE id = ?", (actor_id,)
                ).fetchone()
                tenant_id = int(row[0]) if row else 1
            tenant_id = tenant_id or 1
            if connection.__class__.__name__ == "PostgresConnection":
                connection.execute("SELECT pg_advisory_xact_lock(?)", (tenant_id,))
            previous = connection.execute(
                """SELECT event_hash FROM audit_events
                   WHERE tenant_id = ? AND event_hash IS NOT NULL
                   ORDER BY id DESC LIMIT 1""",
                (tenant_id,),
            ).fetchone()
            previous_hash = previous[0] if previous else GENESIS_HASH
            created_at = datetime.now(timezone.utc).isoformat()
            encoded_details = json.dumps(
                details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            event = {
                "actor_id": actor_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": str(resource_id) if resource_id is not None else None,
                "details": json.loads(encoded_details),
                "created_at": created_at,
                "tenant_id": tenant_id,
            }
            event_hash = _event_hash(previous_hash, event)
            connection.execute(
                """INSERT INTO audit_events
                   (actor_id, action, resource_type, resource_id, details_json,
                    created_at, tenant_id, previous_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    actor_id,
                    action,
                    resource_type,
                    str(resource_id) if resource_id is not None else None,
                    encoded_details,
                    created_at,
                    tenant_id,
                    previous_hash,
                    event_hash,
                ),
            )
        LOGGER.info("security_audit", extra={"security_event": event | {"event_hash": event_hash}})
        return event_hash
    except Exception:
        LOGGER.exception("Failed to persist audit event", extra={"action": action})
        if os.environ.get("AEGIS_ENV", "development").lower() == "production":
            raise
        return None


def verify_audit_chain(tenant_id: int = 1) -> dict:
    """Verify every cryptographically chained event for a tenant."""
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, actor_id, action, resource_type, resource_id,
                      details_json, created_at, previous_hash, event_hash
               FROM audit_events WHERE tenant_id = ? AND event_hash IS NOT NULL
               ORDER BY id""",
            (tenant_id,),
        ).fetchall()
    previous_hash = GENESIS_HASH
    for row in rows:
        try:
            details = json.loads(row[5])
        except (TypeError, json.JSONDecodeError):
            record_audit_integrity_failure()
            return {"valid": False, "events": len(rows), "failed_event_id": int(row[0])}
        event = {
            "actor_id": row[1],
            "action": row[2],
            "resource_type": row[3],
            "resource_id": row[4],
            "details": details,
            "created_at": row[6],
            "tenant_id": tenant_id,
        }
        if row[7] != previous_hash or not hmac.compare_digest(
            row[8], _event_hash(previous_hash, event)
        ):
            record_audit_integrity_failure()
            return {"valid": False, "events": len(rows), "failed_event_id": int(row[0])}
        previous_hash = row[8]
    return {"valid": True, "events": len(rows), "head_hash": previous_hash}


def list_audit_events(limit: int = 200, tenant_id: int = 1):
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, actor_id, action, resource_type, resource_id,
                      details_json, created_at, previous_hash, event_hash
               FROM audit_events WHERE tenant_id = ? ORDER BY id DESC LIMIT ?""",
            (tenant_id, max(1, min(limit, 500))),
        ).fetchall()
    return [
        {
            "id": int(row[0]),
            "actor_id": row[1],
            "action": row[2],
            "resource_type": row[3],
            "resource_id": row[4],
            "details": json.loads(row[5]),
            "created_at": row[6],
            "previous_hash": row[7],
            "event_hash": row[8],
        }
        for row in rows
    ]
