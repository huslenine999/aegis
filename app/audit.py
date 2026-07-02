import json
from datetime import datetime, timezone

try:
    from database import get_connection
except ImportError:
    from .database import get_connection


def record_audit(actor_id, action: str, resource_type: str, resource_id=None, details=None):
    try:
        with get_connection() as connection:
            connection.execute(
                """INSERT INTO audit_events
                   (actor_id, action, resource_type, resource_id, details_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    actor_id,
                    action,
                    resource_type,
                    str(resource_id) if resource_id is not None else None,
                    json.dumps(details or {}, separators=(",", ":")),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except Exception:
        pass


def list_audit_events(limit: int = 200):
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, actor_id, action, resource_type, resource_id,
                      details_json, created_at
               FROM audit_events ORDER BY id DESC LIMIT ?""",
            (max(1, min(limit, 500)),),
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
        }
        for row in rows
    ]
