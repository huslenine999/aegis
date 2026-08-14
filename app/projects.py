import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .database import USING_POSTGRES, get_connection
from .github_lifecycle import ensure_legacy_repository_binding, revoke_github_capabilities


PROJECT_ROLE_LEVEL = {"viewer": 10, "operator": 20, "admin": 30}
VALID_PRESETS = {"quick", "standard", "deep"}
GITHUB_PATH_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_github_repository_url(repository_url: str) -> str:
    """Return a clone-safe HTTPS GitHub URL from common onboarding inputs."""
    value = str(repository_url or "").strip()
    if not value:
        return ""
    if any(character in value for character in ("\r", "\n", "\0")):
        raise ValueError("Invalid GitHub repository URL.")
    if value.startswith("www.github.com/"):
        value = value.removeprefix("www.")
    if value.startswith("github.com/"):
        value = f"https://{value}"
    elif GITHUB_PATH_PATTERN.fullmatch(value.rstrip("/")):
        value = f"https://github.com/{value.rstrip('/')}"

    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Only HTTPS GitHub repositories are supported.")
    path = parsed.path.strip("/")
    if not GITHUB_PATH_PATTERN.fullmatch(path):
        raise ValueError(
            "GitHub repository must be in owner/repository form."
        )
    owner, repository = path.removesuffix(".git").split("/", 1)
    if owner in {".", ".."} or repository in {".", ".."}:
        raise ValueError("Invalid GitHub repository URL.")
    return f"https://github.com/{owner}/{repository}.git"


def _tenant_for_user(connection, user_id: int) -> int:
    row = connection.execute(
        "SELECT tenant_id FROM auth_users WHERE id = ? AND active = 1", (user_id,)
    ).fetchone()
    if not row:
        raise ValueError("Active user not found.")
    return int(row[0])


def create_project(
    *,
    name: str,
    repository_url: str,
    github_full_name: str,
    default_branch: str,
    scan_preset: str,
    user_id: int,
    tenant_id: int | None = None,
) -> int:
    if scan_preset not in VALID_PRESETS:
        raise ValueError("Invalid scan preset.")
    repository_url = normalize_github_repository_url(repository_url)
    github_full_name = str(github_full_name or "").strip()
    with get_connection() as connection:
        user_tenant_id = _tenant_for_user(connection, user_id)
        if tenant_id is not None and int(tenant_id) != user_tenant_id:
            raise ValueError("Project tenant does not match the creating user.")
        tenant_id = user_tenant_id
        insert_sql = """INSERT INTO projects
               (name, repository_url, github_full_name, default_branch,
                scan_preset, created_by, created_at, tenant_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
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
                tenant_id,
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
        if github_full_name:
            ensure_legacy_repository_binding(
                connection, int(project_id), int(tenant_id), github_full_name
            )
    return int(project_id)


def project_role(
    project_id: int,
    user_id: int,
    global_role: str,
    tenant_id: int | None = None,
) -> str | None:
    with get_connection() as connection:
        user_tenant = tenant_id or _tenant_for_user(connection, user_id)
        project = connection.execute(
            "SELECT tenant_id FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if not project or int(project[0]) != int(user_tenant):
            return None
        if global_role == "admin":
            return "admin"
        row = connection.execute(
            "SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user_id),
        ).fetchone()
    return row[0] if row else None


def require_project_role(
    project_id: int,
    user_id: int,
    global_role: str,
    minimum: str,
    tenant_id: int | None = None,
) -> str:
    role = project_role(project_id, user_id, global_role, tenant_id)
    if not role or PROJECT_ROLE_LEVEL.get(role, 0) < PROJECT_ROLE_LEVEL[minimum]:
        raise PermissionError("Project access denied.")
    return role


def list_projects(
    user_id: int, global_role: str, tenant_id: int | None = None
) -> list[dict]:
    with get_connection() as connection:
        tenant_id = tenant_id or _tenant_for_user(connection, user_id)
        if global_role == "admin":
            rows = connection.execute(
                """SELECT p.id, p.name, p.repository_url, p.github_full_name,
                          p.default_branch, p.scan_preset, 'admin'
                   FROM projects p WHERE p.tenant_id = ? ORDER BY p.created_at DESC""",
                (tenant_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT p.id, p.name, p.repository_url, p.github_full_name,
                          p.default_branch, p.scan_preset, m.role
                   FROM projects p JOIN project_members m ON m.project_id = p.id
                   WHERE m.user_id = ? AND p.tenant_id = ?
                   ORDER BY p.created_at DESC""",
                (user_id, tenant_id),
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


def get_project(project_id: int, tenant_id: int | None = None) -> dict | None:
    with get_connection() as connection:
        sql = """SELECT id, name, repository_url, github_full_name,
                        default_branch, scan_preset, created_by, tenant_id
                 FROM projects WHERE id = ?"""
        parameters: tuple = (project_id,)
        if tenant_id is not None:
            sql += " AND tenant_id = ?"
            parameters = (project_id, tenant_id)
        row = connection.execute(sql, parameters).fetchone()
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
        "tenant_id": int(row[7]),
    }


def update_project(
    project_id: int,
    *,
    name: str,
    repository_url: str,
    default_branch: str,
    scan_preset: str,
) -> None:
    if scan_preset not in VALID_PRESETS:
        raise ValueError("Invalid scan preset.")
    repository_url = normalize_github_repository_url(repository_url)
    with get_connection() as connection:
        cursor = connection.execute(
            """UPDATE projects SET name = ?, repository_url = ?,
               default_branch = ?, scan_preset = ? WHERE id = ?""",
            (name, repository_url or None, default_branch, scan_preset, project_id),
        )
        if not getattr(cursor, "rowcount", 0):
            raise ValueError("Project not found.")


def delete_project(project_id: int) -> list[str]:
    revoke_github_capabilities(project_id=project_id)
    with get_connection() as connection:
        job_ids = [
            row[0]
            for row in connection.execute(
                "SELECT job_id FROM scan_runs WHERE project_id = ?", (project_id,)
            ).fetchall()
        ]
        channel_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM notification_channels WHERE project_id = ?", (project_id,)
            ).fetchall()
        ]
        for channel_id in channel_ids:
            connection.execute(
                "DELETE FROM notification_deliveries WHERE channel_id = ?", (channel_id,)
            )
        connection.execute("DELETE FROM notification_channels WHERE project_id = ?", (project_id,))
        connection.execute("DELETE FROM scan_runs WHERE project_id = ?", (project_id,))
        connection.execute("DELETE FROM project_members WHERE project_id = ?", (project_id,))
        cursor = connection.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        if not getattr(cursor, "rowcount", 0):
            raise ValueError("Project not found.")
    return job_ids


def create_scan_run(
    *,
    job_id: str,
    project_id: int,
    requested_by: int,
    target: str,
    preset: str,
    source_revision: str | None = None,
    source_ref: str | None = None,
    github_installation_id: int | None = None,
    github_pull_request: int | None = None,
    github_check_run_id: int | None = None,
    policy_version_id: int | None = None,
) -> int:
    with get_connection() as connection:
        project = connection.execute(
            "SELECT tenant_id FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if not project:
            raise ValueError("Project not found.")
        tenant_id = int(project[0])
        if _tenant_for_user(connection, requested_by) != tenant_id:
            raise ValueError("Scan requester and project belong to different tenants.")
        if policy_version_id is not None:
            policy = connection.execute(
                """SELECT state FROM project_policies
                   WHERE id = ? AND project_id = ? AND tenant_id = ?""",
                (policy_version_id, project_id, tenant_id),
            ).fetchone()
            if not policy or policy[0] != "approved":
                raise ValueError("Scans must reference an approved project policy.")
        insert_sql = """INSERT INTO scan_runs
               (job_id, project_id, requested_by, target, preset, state,
                progress, created_at, tenant_id, source_revision, source_ref,
                github_installation_id, github_pull_request, github_check_run_id,
                policy_version_id)
               VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?, ?, ?, ?, ?)"""
        if USING_POSTGRES:
            insert_sql += " RETURNING id"
        cursor = connection.execute(
            insert_sql,
            (
                job_id,
                project_id,
                requested_by,
                target,
                preset,
                _now(),
                tenant_id,
                source_revision,
                source_ref,
                github_installation_id,
                github_pull_request,
                github_check_run_id,
                policy_version_id,
            ),
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

    def stable_path(value) -> str:
        text = str(value or "").replace("\\", "/")
        for marker in ("/workspaces/", "/uploads/"):
            if marker not in text:
                continue
            remainder = text.split(marker, 1)[1]
            return remainder.split("/", 1)[1] if "/" in remainder else remainder
        return text

    for item in result.get("ruff") or []:
        values.add(
            f"ruff:{item.get('code')}:{stable_path(item.get('filename'))}:{item.get('message')}"
        )
    for item in (result.get("semgrep") or {}).get("results", []):
        values.add(
            f"semgrep:{item.get('check_id')}:{stable_path(item.get('path'))}:{item.get('extra', {}).get('message')}"
        )
    for family, keys in {
        "osv": ("id", "package"),
        "yara": ("rule", "filename"),
        "clamav": ("virus", "filename"),
        "zap": ("vuln_type", "route"),
    }.items():
        for item in result.get(family) or []:
            parts = [
                stable_path(item.get(key)) if key == "filename" else str(item.get(key))
                for key in keys
            ]
            values.add(f"{family}:" + ":".join(parts))
    safety = result.get("safety") or {}
    if isinstance(safety, dict):
        safety_items = safety.get("vulnerabilities", []) or safety.get("results", [])
    else:
        safety_items = safety
    for item in safety_items or []:
        values.add(
            "safety:"
            + ":".join(
                str(item.get(key))
                for key in ("vulnerability_id", "advisory", "package_name", "package")
            )
        )
    for target in (result.get("trivy") or {}).get("Results", []):
        for item in target.get("Vulnerabilities", []) or []:
            values.add(
                f"trivy:{item.get('VulnerabilityID')}:{target.get('Target')}:{item.get('PkgName')}"
            )
    for filename, items in (result.get("secrets") or {}).get("results", {}).items():
        for item in items:
            values.add(f"secrets:{item.get('type')}:{stable_path(filename)}")
    iac = result.get("iac") or {}
    if isinstance(iac, dict):
        for item in iac.get("findings", []) or []:
            values.add(
                "iac:"
                + ":".join(
                    str(item.get(key))
                    for key in ("rule_id", "framework", "resource")
                )
                + ":"
                + stable_path(item.get("path"))
            )
        for item in iac.get("unmanaged_suppressions", []) or []:
            values.add(
                "iac-suppression:"
                + ":".join(
                    str(item.get(key))
                    for key in ("rule_id", "framework", "resource")
                )
                + ":"
                + stable_path(item.get("path"))
            )
    return values


def update_scan_run(
    run_id: int, *, state: str, progress: int, result: dict | None = None
) -> None:
    with get_connection() as connection:
        new_findings = 0
        result_json = None
        completed_at = None
        if result is not None:
            finding_sync = result.get("finding_sync")
            if isinstance(finding_sync, dict):
                new_findings = int(finding_sync.get("created", 0)) + int(
                    finding_sync.get("reopened", 0)
                )
            else:
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
        if result_json is None:
            # Avoid passing an untyped NULL through COALESCE/CASE. PostgreSQL
            # cannot infer that placeholder's type, which used to make the
            # worker's error handler fail and leave scan runs stuck as queued.
            connection.execute(
                """UPDATE scan_runs SET state = ?, progress = ?,
                   completed_at = COALESCE(?, completed_at)
                   WHERE id = ?""",
                (state, progress, completed_at, run_id),
            )
        else:
            connection.execute(
                """UPDATE scan_runs SET state = ?, progress = ?,
                   result_json = ?, new_findings = ?,
                   completed_at = COALESCE(?, completed_at)
                   WHERE id = ?""",
                (
                    state,
                    progress,
                    result_json,
                    new_findings,
                    completed_at,
                    run_id,
                ),
            )


def get_scan_run(run_id: int, tenant_id: int | None = None) -> dict | None:
    with get_connection() as connection:
        sql = """SELECT id, job_id, project_id, requested_by, target, preset,
                      state, progress, result_json, new_findings, created_at,
                      completed_at, tenant_id, source_revision, source_ref,
                      github_installation_id, github_pull_request,
                      github_check_run_id, policy_version_id
               FROM scan_runs WHERE id = ?"""
        parameters: tuple = (run_id,)
        if tenant_id is not None:
            sql += " AND tenant_id = ?"
            parameters = (run_id, tenant_id)
        row = connection.execute(sql, parameters).fetchone()
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
        "tenant_id": int(row[12]),
        "source_revision": row[13],
        "source_ref": row[14],
        "github_installation_id": int(row[15]) if row[15] is not None else None,
        "github_pull_request": int(row[16]) if row[16] is not None else None,
        "github_check_run_id": int(row[17]) if row[17] is not None else None,
        "policy_version_id": int(row[18]) if row[18] is not None else None,
    }


def list_scan_runs(project_id: int, limit: int = 50) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, job_id, project_id, requested_by, target, preset,
                      state, progress, new_findings, created_at, completed_at
               FROM scan_runs WHERE project_id = ?
               ORDER BY id DESC LIMIT ?""",
            (project_id, max(1, min(limit, 100))),
        ).fetchall()
    return [
        {
            "id": int(row[0]),
            "job_id": row[1],
            "project_id": int(row[2]),
            "requested_by": int(row[3]),
            "target": row[4],
            "preset": row[5],
            "state": row[6],
            "progress": int(row[7]),
            "new_findings": int(row[8]),
            "created_at": row[9],
            "completed_at": row[10],
        }
        for row in rows
    ]


def record_scan_artifacts(scan_run_id: int, artifacts: list[dict]) -> None:
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM scan_artifacts WHERE scan_run_id = ?", (scan_run_id,)
        )
        if artifacts:
            connection.executemany(
                """INSERT INTO scan_artifacts
                   (scan_run_id, name, size_bytes, sha256, created_at,
                    backend, storage_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        scan_run_id,
                        str(artifact["name"]),
                        int(artifact["size"]),
                        str(artifact["sha256"]),
                        _now(),
                        str(artifact.get("backend") or "local"),
                        artifact.get("storage_key"),
                    )
                    for artifact in artifacts
                ],
            )


def list_scan_artifacts(scan_run_id: int) -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT name, size_bytes, sha256, created_at, backend, storage_key
               FROM scan_artifacts WHERE scan_run_id = ? ORDER BY name""",
            (scan_run_id,),
        ).fetchall()
    return [
        {
            "name": row[0],
            "size": int(row[1]),
            "sha256": row[2],
            "created_at": row[3],
            "backend": row[4],
            "storage_key": row[5],
        }
        for row in rows
    ]


def get_scan_artifact(scan_run_id: int, name: str) -> dict | None:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT name, size_bytes, sha256, created_at, backend, storage_key
               FROM scan_artifacts WHERE scan_run_id = ? AND name = ?""",
            (scan_run_id, name),
        ).fetchone()
    if not row:
        return None
    return {
        "name": row[0],
        "size": int(row[1]),
        "sha256": row[2],
        "created_at": row[3],
        "backend": row[4],
        "storage_key": row[5],
    }


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
        project = connection.execute(
            "SELECT tenant_id FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if not project:
            raise ValueError("Project not found.")
        user = connection.execute(
            """SELECT id, username FROM auth_users
               WHERE username = ? AND active = 1 AND tenant_id = ?""",
            (username, project[0]),
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


def remove_project_member(project_id: int, user_id: int) -> bool:
    with get_connection() as connection:
        admins = connection.execute(
            "SELECT COUNT(*) FROM project_members WHERE project_id = ? AND role = 'admin'",
            (project_id,),
        ).fetchone()[0]
        member = connection.execute(
            "SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user_id),
        ).fetchone()
        if not member:
            return False
        if member[0] == "admin" and admins <= 1:
            raise ValueError("At least one project administrator is required.")
        cursor = connection.execute(
            "DELETE FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user_id),
        )
    return bool(getattr(cursor, "rowcount", 0))
