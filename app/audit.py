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
        environment = os.environ.get("AEGIS_ENV", "development").strip().lower()
        if environment == "production":
            raise RuntimeError(
                "AEGIS_AUDIT_HMAC_KEY must be set in production; refusing to "
                "sign audit events with a development fallback key."
            )
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


def _failure(rows: list, event_id: int | None, reason: str) -> dict:
    record_audit_integrity_failure()
    result: dict = {"valid": False, "events": len(rows), "reason": reason}
    if event_id is not None:
        result["failed_event_id"] = event_id
    return result


def verify_audit_chain(tenant_id: int = 1, checkpoints: list | None = None) -> dict:
    """Verify every chained event for a tenant, and optionally external checkpoints.

    The hash chain detects edited, inserted, or deleted events inside the chain,
    but a chain whose newest events were deleted, or a restored older database,
    is still internally valid. A checkpoint is a chain head exported earlier to
    a separately administered store; verification fails if the chain no longer
    contains that exact event at that position.
    """
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, actor_id, action, resource_type, resource_id,
                      details_json, created_at, previous_hash, event_hash
               FROM audit_events WHERE tenant_id = ?
               ORDER BY id""",
            (tenant_id,),
        ).fetchall()
    previous_hash = GENESIS_HASH
    positions: dict[int, tuple[int, str]] = {}
    for position, row in enumerate(rows, start=1):
        if not row[7] or not row[8]:
            return _failure(rows, int(row[0]), "unchained event")
        try:
            details = json.loads(row[5])
        except (TypeError, json.JSONDecodeError):
            return _failure(rows, int(row[0]), "unreadable event details")
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
            return _failure(rows, int(row[0]), "hash mismatch")
        previous_hash = row[8]
        positions[int(row[0])] = (position, row[8])

    verified = 0
    for checkpoint in checkpoints or []:
        try:
            if int(checkpoint["tenant_id"]) != tenant_id:
                return _failure(rows, None, "checkpoint belongs to another tenant")
            event_id = int(checkpoint["event_id"])
            expected_hash = str(checkpoint["event_hash"])
            expected_position = int(checkpoint["events"])
        except (KeyError, TypeError, ValueError):
            return _failure(rows, None, "malformed checkpoint")
        found = positions.get(event_id)
        if found is None:
            return _failure(rows, event_id, "checkpointed event is missing (truncation or rollback)")
        if found[0] != expected_position or not hmac.compare_digest(found[1], expected_hash):
            return _failure(rows, event_id, "checkpointed event does not match the chain")
        verified += 1
    return {
        "valid": True,
        "events": len(rows),
        "head_hash": previous_hash,
        "checkpoints_verified": verified,
    }


def create_audit_checkpoint(tenant_id: int = 1) -> dict:
    """Return the current chain head for storage outside Aegis.

    Store checkpoints where the Aegis database administrator cannot rewrite
    them (a SIEM, WORM storage, or a ticket). Without the audit HMAC key, a
    checkpoint cannot be forged to match a rewritten chain.
    """
    verification = verify_audit_chain(tenant_id)
    if not verification["valid"]:
        raise ValueError("The audit chain is invalid; refusing to checkpoint it.")
    if not verification["events"]:
        raise ValueError("The audit chain has no events to checkpoint yet.")
    with get_connection() as connection:
        event_id = connection.execute(
            "SELECT MAX(id) FROM audit_events WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()[0]
    return {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "event_id": int(event_id),
        "event_hash": verification["head_hash"],
        "events": verification["events"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


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
