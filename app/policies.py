import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .database import USING_POSTGRES, get_connection
from .findings import extract_findings


SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
KNOWN_TOOLS = {
    "Ruff", "Semgrep", "Safety", "OSV", "Trivy", "Secrets", "YARA",
    "ClamAV", "DAST",
}
DEFAULT_DEFINITION = {
    "schema_version": 1,
    "fail_on_severities": ["MEDIUM", "HIGH", "CRITICAL"],
    "required_tools": [],
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_definition(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Policy definition must be an object.")
    unknown = set(value) - {"schema_version", "fail_on_severities", "required_tools"}
    if unknown:
        raise ValueError("Unsupported policy fields: " + ", ".join(sorted(unknown)))
    if value.get("schema_version", 1) != 1:
        raise ValueError("Unsupported policy schema version.")
    fail_on = value.get("fail_on_severities", DEFAULT_DEFINITION["fail_on_severities"])
    if not isinstance(fail_on, list):
        raise ValueError("fail_on_severities must be a list.")
    normalized_fail_on = sorted({str(item).upper() for item in fail_on})
    if set(normalized_fail_on) - SEVERITIES:
        raise ValueError("Policy contains an invalid severity.")
    required_tools = value.get("required_tools", [])
    if not isinstance(required_tools, list):
        raise ValueError("required_tools must be a list.")
    normalized_tools = sorted({str(item).strip() for item in required_tools if str(item).strip()})
    if set(normalized_tools) - KNOWN_TOOLS:
        raise ValueError("Policy contains an unknown required tool.")
    return {
        "schema_version": 1,
        "fail_on_severities": normalized_fail_on,
        "required_tools": normalized_tools,
    }


def _serialize(definition: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    normalized = normalize_definition(definition)
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return normalized, encoded, hashlib.sha256(encoded.encode()).hexdigest()


def _row_to_policy(row) -> dict[str, Any]:
    return {
        "id": int(row[0]),
        "project_id": int(row[1]),
        "version": int(row[2]),
        "name": row[3],
        "definition": json.loads(row[4]),
        "sha256": row[5],
        "state": row[6],
        "created_by": int(row[7]),
        "approved_by": int(row[8]) if row[8] is not None else None,
        "created_at": row[9],
        "approved_at": row[10],
    }


def list_policies(project_id: int) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, project_id, version, name, definition_json,
                      definition_sha256, state, created_by, approved_by,
                      created_at, approved_at
               FROM project_policies WHERE project_id = ? ORDER BY version DESC""",
            (project_id,),
        ).fetchall()
    return [_row_to_policy(row) for row in rows]


def get_policy(policy_id: int, project_id: int | None = None) -> dict[str, Any] | None:
    sql = """SELECT id, project_id, version, name, definition_json,
                    definition_sha256, state, created_by, approved_by,
                    created_at, approved_at
             FROM project_policies WHERE id = ?"""
    parameters: tuple[Any, ...] = (policy_id,)
    if project_id is not None:
        sql += " AND project_id = ?"
        parameters = (policy_id, project_id)
    with get_connection() as connection:
        row = connection.execute(sql, parameters).fetchone()
    return _row_to_policy(row) if row else None


def active_policy(project_id: int) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT id, project_id, version, name, definition_json,
                      definition_sha256, state, created_by, approved_by,
                      created_at, approved_at
               FROM project_policies WHERE project_id = ? AND state = 'approved'
               ORDER BY version DESC LIMIT 1""",
            (project_id,),
        ).fetchone()
    return _row_to_policy(row) if row else None


def create_policy(
    project_id: int,
    actor_id: int,
    name: str,
    definition: dict[str, Any],
    *,
    approve: bool = False,
) -> dict[str, Any]:
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 120:
        raise ValueError("Policy name must contain 1 to 120 characters.")
    _, encoded, digest = _serialize(definition)
    now = _now()
    with get_connection() as connection:
        project = connection.execute(
            "SELECT tenant_id FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        user = connection.execute(
            "SELECT tenant_id FROM auth_users WHERE id = ? AND active = 1", (actor_id,)
        ).fetchone()
        if not project or not user or int(project[0]) != int(user[0]):
            raise ValueError("Project and policy author must share a tenant.")
        duplicate = connection.execute(
            """SELECT id FROM project_policies
               WHERE project_id = ? AND definition_sha256 = ?""",
            (project_id, digest),
        ).fetchone()
        if duplicate:
            raise ValueError("An identical policy version already exists.")
        version_row = connection.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM project_policies WHERE project_id = ?",
            (project_id,),
        ).fetchone()
        version = int(version_row[0])
        if approve:
            connection.execute(
                """UPDATE project_policies SET state = 'retired'
                   WHERE project_id = ? AND state = 'approved'""",
                (project_id,),
            )
        insert = """INSERT INTO project_policies
            (tenant_id, project_id, version, name, definition_json,
             definition_sha256, state, created_by, approved_by, created_at,
             approved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        if USING_POSTGRES:
            insert += " RETURNING id"
        cursor = connection.execute(
            insert,
            (
                int(project[0]), project_id, version, clean_name, encoded, digest,
                "approved" if approve else "draft", actor_id,
                actor_id if approve else None, now, now if approve else None,
            ),
        )
        policy_id = (
            int(cursor.fetchone()[0])
            if USING_POSTGRES
            else int(getattr(cursor, "lastrowid"))
        )
    policy = get_policy(policy_id, project_id)
    if not policy:
        raise ValueError("Policy was not persisted.")
    return policy


def ensure_active_policy(project_id: int, actor_id: int) -> dict[str, Any]:
    policy = active_policy(project_id)
    if policy:
        return policy
    return create_policy(
        project_id,
        actor_id,
        "Default security gate",
        DEFAULT_DEFINITION,
        approve=True,
    )


def approve_policy(project_id: int, policy_id: int, actor_id: int) -> dict[str, Any]:
    now = _now()
    with get_connection() as connection:
        row = connection.execute(
            """SELECT state FROM project_policies
               WHERE id = ? AND project_id = ?""",
            (policy_id, project_id),
        ).fetchone()
        if not row:
            raise ValueError("Policy version not found.")
        if row[0] != "draft":
            raise ValueError("Only draft policy versions can be approved.")
        connection.execute(
            """UPDATE project_policies SET state = 'retired'
               WHERE project_id = ? AND state = 'approved'""",
            (project_id,),
        )
        connection.execute(
            """UPDATE project_policies SET state = 'approved', approved_by = ?,
               approved_at = ? WHERE id = ?""",
            (actor_id, now, policy_id),
        )
    policy = get_policy(policy_id, project_id)
    if not policy:
        raise ValueError("Policy version not found after approval.")
    return policy


def simulate_policy(project_id: int, scan_run_id: int, definition: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_definition(definition)
    with get_connection() as connection:
        row = connection.execute(
            """SELECT result_json FROM scan_runs
               WHERE id = ? AND project_id = ? AND state = 'completed'""",
            (scan_run_id, project_id),
        ).fetchone()
    if not row or not row[0]:
        raise ValueError("A completed scan with results is required for simulation.")
    result = json.loads(row[0])
    findings = extract_findings(result)
    blocking = [
        item for item in findings
        if item["severity"] in set(normalized["fail_on_severities"])
    ]
    tool_states = {
        str(item.get("name")): str(item.get("status"))
        for item in result.get("tools", [])
    }
    unavailable = [
        tool for tool in normalized["required_tools"]
        if tool_states.get(tool) != "completed"
    ]
    status = "ERROR" if unavailable else "BLOCKED" if blocking else "PASSED"
    return {
        "scan_run_id": scan_run_id,
        "status": status,
        "blocking_findings": len(blocking),
        "blocking_by_severity": {
            severity: sum(1 for item in blocking if item["severity"] == severity)
            for severity in sorted(SEVERITIES)
            if any(item["severity"] == severity for item in blocking)
        },
        "unavailable_required_tools": unavailable,
        "definition": normalized,
    }
