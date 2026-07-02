import json
from datetime import datetime, timezone

try:
    from database import USING_POSTGRES, get_connection
except ImportError:
    from .database import USING_POSTGRES, get_connection


PROJECT_ROLE_LEVEL = {"viewer": 10, "operator": 20, "admin": 30}
VALID_PRESETS = {"quick", "standard", "deep"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_project(
    *,
    name: str,
    repository_url: str,
    github_full_name: str,
    default_branch: str,
    scan_preset: str,
    user_id: int,
) -> int:
    if scan_preset not in VALID_PRESETS:
        raise ValueError("Invalid scan preset.")
    with get_connection() as connection:
        insert_sql = """INSERT INTO projects
               (name, repository_url, github_full_name, default_branch,
                scan_preset, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)"""
        if USING_POSTGRES:
            insert_sql += " RETURNING id"
        cursor = connection.execute(
            insert_sql,
            (
                name,
                repository_url,
                github_full_name or None,
                default_branch or "main",
                scan_preset,
                user_id,
                _now(),
            ),
        )
        project_id = cursor.fetchone()[0] if USING_POSTGRES else getattr(cursor, "lastrowid", None)
        if project_id is None:
            project_id = connection.execute(
                "SELECT id FROM projects WHERE created_by = ? ORDER BY id DESC LIMIT 1",
                (user_id,),
            ).fetchone()[0]
        connection.execute(
            """INSERT INTO project_members (project_id, user_id, role, created_at)
               VALUES (?, ?, ?, ?)""",
            (project_id, user_id, "admin", _now()),
        )
    return int(project_id)


def project_role(project_id: int, user_id: int, global_role: str) -> str | None:
    if global_role == "admin":
        return "admin"
    with get_connection() as connection:
        row = connection.execute(
            "SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user_id),
        ).fetchone()
    return row[0] if row else None


def require_project_role(project_id: int, user_id: int, global_role: str, minimum: str) -> str:
    role = project_role(project_id, user_id, global_role)
    if not role or PROJECT_ROLE_LEVEL.get(role, 0) < PROJECT_ROLE_LEVEL[minimum]:
        raise PermissionError("Project access denied.")
    return role


def list_projects(user_id: int, global_role: str) -> list[dict]:
    with get_connection() as connection:
        if global_role == "admin":
            rows = connection.execute(
                """SELECT p.id, p.name, p.repository_url, p.github_full_name,
                          p.default_branch, p.scan_preset, 'admin'
                   FROM projects p ORDER BY p.created_at DESC"""
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT p.id, p.name, p.repository_url, p.github_full_name,
                          p.default_branch, p.scan_preset, m.role
                   FROM projects p JOIN project_members m ON m.project_id = p.id
                   WHERE m.user_id = ? ORDER BY p.created_at DESC""",
                (user_id,),
            ).fetchall()
    return [
        {
            "id": int(row[0]),
            "name": row[1],
            "repository_url": row[2] or "",
            "github_full_name": row[3] or "",
            "default_branch": row[4],
            "scan_preset": row[5],
            "role": row[6],
        }
        for row in rows
    ]


def get_project(project_id: int) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT id, name, repository_url, github_full_name,
                      default_branch, scan_preset, created_by
               FROM projects WHERE id = ?""",
            (project_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "id": int(row[0]),
        "name": row[1],
        "repository_url": row[2] or "",
        "github_full_name": row[3] or "",
        "default_branch": row[4],
        "scan_preset": row[5],
        "created_by": int(row[6]),
    }


def create_scan_run(
    *, job_id: str, project_id: int, requested_by: int, target: str, preset: str
) -> int:
    with get_connection() as connection:
        insert_sql = """INSERT INTO scan_runs
               (job_id, project_id, requested_by, target, preset, state,
                progress, created_at)
               VALUES (?, ?, ?, ?, ?, 'queued', 0, ?)"""
        if USING_POSTGRES:
            insert_sql += " RETURNING id"
        cursor = connection.execute(
            insert_sql,
            (job_id, project_id, requested_by, target, preset, _now()),
        )
        run_id = cursor.fetchone()[0] if USING_POSTGRES else getattr(cursor, "lastrowid", None)
        if run_id is None:
            run_id = connection.execute(
                "SELECT id FROM scan_runs WHERE job_id = ?", (job_id,)
            ).fetchone()[0]
    return int(run_id)


def _fingerprints(result: dict | None) -> set[str]:
    result = result or {}
    values = set()
    for item in result.get("ruff") or []:
        values.add(f"ruff:{item.get('code')}:{item.get('filename')}:{item.get('location')}")
    for item in (result.get("semgrep") or {}).get("results", []):
        values.add(f"semgrep:{item.get('check_id')}:{item.get('path')}:{item.get('start')}")
    for family, keys in {
        "osv": ("id", "package"),
        "clamav": ("virus", "filename"),
        "zap": ("vuln_type", "route"),
    }.items():
        for item in result.get(family) or []:
            values.add(f"{family}:" + ":".join(str(item.get(key)) for key in keys))
    return values


def update_scan_run(
    run_id: int, *, state: str, progress: int, result: dict | None = None
) -> None:
    with get_connection() as connection:
        new_findings = 0
        result_json = None
        completed_at = None
        if result is not None:
            row = connection.execute(
                "SELECT project_id FROM scan_runs WHERE id = ?", (run_id,)
            ).fetchone()
            previous = connection.execute(
                """SELECT result_json FROM scan_runs
                   WHERE project_id = ? AND id != ? AND state = 'completed'
                   AND result_json IS NOT NULL ORDER BY id DESC LIMIT 1""",
                (row[0], run_id),
            ).fetchone()
            previous_result = json.loads(previous[0]) if previous and previous[0] else {}
            new_findings = len(_fingerprints(result) - _fingerprints(previous_result))
            result["new_findings"] = new_findings
            result_json = json.dumps(result, separators=(",", ":"))
        if state in {"completed", "failed", "cancelled"}:
            completed_at = _now()
        connection.execute(
            """UPDATE scan_runs SET state = ?, progress = ?,
               result_json = COALESCE(?, result_json),
               new_findings = CASE WHEN ? IS NULL THEN new_findings ELSE ? END,
               completed_at = COALESCE(?, completed_at)
               WHERE id = ?""",
            (
                state,
                progress,
                result_json,
                result_json,
                new_findings,
                completed_at,
                run_id,
            ),
        )


def get_scan_run(run_id: int) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT id, job_id, project_id, requested_by, target, preset,
                      state, progress, result_json, new_findings, created_at,
                      completed_at
               FROM scan_runs WHERE id = ?""",
            (run_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "id": int(row[0]),
        "job_id": row[1],
        "project_id": int(row[2]),
        "requested_by": int(row[3]),
        "target": row[4],
        "preset": row[5],
        "state": row[6],
        "progress": int(row[7]),
        "result": json.loads(row[8]) if row[8] else None,
        "new_findings": int(row[9]),
        "created_at": row[10],
        "completed_at": row[11],
    }


def list_scan_runs(project_id: int, limit: int = 50) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id FROM scan_runs WHERE project_id = ?
               ORDER BY id DESC LIMIT ?""",
            (project_id, max(1, min(limit, 100))),
        ).fetchall()
    return [get_scan_run(int(row[0])) for row in rows]


def list_project_members(project_id: int) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT u.id, u.username, m.role
               FROM project_members m JOIN auth_users u ON u.id = m.user_id
               WHERE m.project_id = ? ORDER BY u.username""",
            (project_id,),
        ).fetchall()
    return [
        {"user_id": int(row[0]), "username": row[1], "role": row[2]}
        for row in rows
    ]


def set_project_member(project_id: int, username: str, role: str) -> dict:
    if role not in PROJECT_ROLE_LEVEL:
        raise ValueError("Invalid project role.")
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, username FROM auth_users WHERE username = ? AND active = 1",
            (username,),
        ).fetchone()
        if not user:
            raise ValueError("Active user not found.")
        updated = connection.execute(
            """UPDATE project_members SET role = ?
               WHERE project_id = ? AND user_id = ?""",
            (role, project_id, user[0]),
        )
        if not getattr(updated, "rowcount", 0):
            connection.execute(
                """INSERT INTO project_members (project_id, user_id, role, created_at)
                   VALUES (?, ?, ?, ?)""",
                (project_id, user[0], role, _now()),
            )
    return {"user_id": int(user[0]), "username": user[1], "role": role}
