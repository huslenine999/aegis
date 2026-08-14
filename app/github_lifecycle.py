"""Tenant-bound GitHub identity and capability lifecycle controls.

GitHub webhook fields and queue payloads are untrusted transport data.  This
module is the database-backed boundary that turns them into a usable
capability only when the installation, repository, project, and tenant agree.
Legacy project rows are represented as explicit ``legacy`` bindings until an
exact repository and installation identity is observed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .database import get_connection


GITHUB_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubLifecycleError(ValueError):
    """Raised when a GitHub capability cannot be proven for its tenant."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _repository_name(value: str) -> str:
    name = str(value or "").strip()
    if not GITHUB_REPOSITORY_RE.fullmatch(name):
        raise GitHubLifecycleError("GitHub repository identity is invalid.")
    return name


def _positive_id(value: int, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise GitHubLifecycleError(f"GitHub {label} is invalid.") from exc
    if result < 1:
        raise GitHubLifecycleError(f"GitHub {label} is invalid.")
    return result


def _binding_row(connection, project_id: int):
    return connection.execute(
        """SELECT id, project_id, tenant_id, installation_id, repository_id,
                  repository_full_name, state, created_at, last_seen_at, revoked_at
           FROM github_repository_bindings WHERE project_id = ?""",
        (project_id,),
    ).fetchone()


def _binding_dict(row) -> dict:
    return {
        "id": int(row[0]),
        "project_id": int(row[1]),
        "tenant_id": int(row[2]),
        "installation_id": int(row[3]) if row[3] is not None else None,
        "repository_id": int(row[4]) if row[4] is not None else None,
        "repository_full_name": row[5],
        "state": row[6],
        "created_at": row[7],
        "last_seen_at": row[8],
        "revoked_at": row[9],
    }


def _route_for_binding(connection, project_id: int):
    return connection.execute(
        """SELECT b.id, b.project_id, b.tenant_id, b.installation_id,
                  b.repository_id, b.repository_full_name, b.state,
                  b.created_at, b.last_seen_at, b.revoked_at,
                  p.created_by, u.username, u.role
           FROM github_repository_bindings b
           JOIN projects p ON p.id = b.project_id AND p.tenant_id = b.tenant_id
           JOIN auth_users u ON u.id = p.created_by AND u.tenant_id = b.tenant_id
           WHERE b.project_id = ? AND b.state = 'active' AND u.active = 1""",
        (project_id,),
    ).fetchone()


def _route_dict(row) -> dict:
    return {
        "id": int(row[0]),
        "project_id": int(row[1]),
        "tenant_id": int(row[2]),
        "installation_id": int(row[3]),
        "repository_id": int(row[4]),
        "repository_full_name": row[5],
        "state": row[6],
        "created_at": row[7],
        "last_seen_at": row[8],
        "revoked_at": row[9],
        "created_by": int(row[10]),
        "username": row[11],
        "role": row[12],
    }


def ensure_legacy_repository_binding(
    connection, project_id: int, tenant_id: int, repository_full_name: str
) -> None:
    """Create a non-trusted placeholder for a project imported before Phase 5."""
    name = _repository_name(repository_full_name)
    existing = _binding_row(connection, project_id)
    if existing:
        if int(existing[2]) != int(tenant_id) or existing[5] != name:
            raise GitHubLifecycleError("GitHub repository mapping is immutable.")
        return
    now = _now()
    connection.execute(
        """INSERT INTO github_repository_bindings
           (project_id, tenant_id, installation_id, repository_id,
            repository_full_name, state, created_at, last_seen_at, revoked_at)
           VALUES (?, ?, NULL, NULL, ?, 'legacy', ?, ?, NULL)""",
        (int(project_id), int(tenant_id), name, now, now),
    )


def backfill_github_repository_bindings() -> dict:
    """Backfill legacy placeholders without granting App access.

    Ambiguous repository names remain ``legacy`` and are reported.  They are
    deliberately not promoted by webhook routing.
    """
    created = 0
    invalid: list[dict] = []
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, tenant_id, github_full_name FROM projects
               WHERE github_full_name IS NOT NULL AND TRIM(github_full_name) <> ''
               ORDER BY id"""
        ).fetchall()
        for project_id, tenant_id, full_name in rows:
            try:
                name = _repository_name(full_name)
            except GitHubLifecycleError:
                invalid.append({"project_id": int(project_id), "repository": str(full_name)})
                continue
            if _binding_row(connection, int(project_id)):
                continue
            ensure_legacy_repository_binding(connection, int(project_id), int(tenant_id), name)
            created += 1

        ambiguous_rows = connection.execute(
            """SELECT repository_full_name, COUNT(*) FROM github_repository_bindings
               WHERE state = 'legacy' GROUP BY repository_full_name HAVING COUNT(*) > 1
               ORDER BY repository_full_name"""
        ).fetchall()
    return {
        "created": created,
        "ambiguous": [
            {"repository": row[0], "count": int(row[1])}
            for row in ambiguous_rows
        ],
        "invalid": invalid,
    }


def _ensure_installation(connection, installation_id: int, tenant_id: int) -> None:
    now = _now()
    row = connection.execute(
        """SELECT tenant_id, state FROM github_installations
           WHERE installation_id = ?""",
        (installation_id,),
    ).fetchone()
    if row:
        if int(row[0]) != int(tenant_id):
            raise GitHubLifecycleError("GitHub installation belongs to another tenant.")
        if row[1] != "active":
            raise GitHubLifecycleError("GitHub installation is revoked.")
        connection.execute(
            "UPDATE github_installations SET last_seen_at = ? WHERE installation_id = ?",
            (now, installation_id),
        )
        return
    connection.execute(
        """INSERT INTO github_installations
           (installation_id, tenant_id, state, created_at, last_seen_at, revoked_at)
           VALUES (?, ?, 'active', ?, ?, NULL)""",
        (installation_id, tenant_id, now, now),
    )


def _active_conflict(connection, *, project_id: int, repository_id: int, name: str) -> bool:
    by_id = connection.execute(
        """SELECT project_id FROM github_repository_bindings
           WHERE state = 'active' AND repository_id = ? AND project_id <> ?""",
        (repository_id, project_id),
    ).fetchone()
    if by_id:
        return True
    by_name = connection.execute(
        """SELECT project_id FROM github_repository_bindings
           WHERE state = 'active' AND repository_full_name = ? AND project_id <> ?""",
        (name, project_id),
    ).fetchone()
    return bool(by_name)


def bind_github_repository(
    *,
    project_id: int,
    tenant_id: int,
    installation_id: int,
    repository_id: int,
    repository_full_name: str,
) -> dict:
    """Bind one GitHub App installation and repository to one project.

    A legacy placeholder may be promoted once.  Active and revoked mappings
    cannot be retargeted or resurrected.
    """
    project_id = _positive_id(project_id, "project ID")
    tenant_id = _positive_id(tenant_id, "tenant ID")
    installation_id = _positive_id(installation_id, "installation ID")
    repository_id = _positive_id(repository_id, "repository ID")
    name = _repository_name(repository_full_name)
    with get_connection() as connection:
        project = connection.execute(
            "SELECT tenant_id, github_full_name FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if not project:
            raise GitHubLifecycleError("GitHub project was not found.")
        if int(project[0]) != tenant_id:
            raise GitHubLifecycleError("GitHub project belongs to another tenant.")
        if project[1] and project[1] != name:
            raise GitHubLifecycleError("GitHub repository mapping is immutable.")
        if not project[1]:
            connection.execute(
                "UPDATE projects SET github_full_name = ? WHERE id = ? AND tenant_id = ?",
                (name, project_id, tenant_id),
            )

        existing = _binding_row(connection, project_id)
        if existing:
            if int(existing[2]) != tenant_id or existing[5] != name:
                raise GitHubLifecycleError("GitHub repository mapping is immutable.")
            if existing[6] == "revoked":
                raise GitHubLifecycleError("GitHub repository mapping is revoked.")
            if existing[6] == "active":
                if int(existing[3]) != installation_id or int(existing[4]) != repository_id:
                    raise GitHubLifecycleError("GitHub repository mapping is immutable.")
                _ensure_installation(connection, installation_id, tenant_id)
                route = _route_for_binding(connection, project_id)
                if not route:
                    raise GitHubLifecycleError("GitHub project owner is inactive.")
                return _route_dict(route)

        if _active_conflict(
            connection, project_id=project_id, repository_id=repository_id, name=name
        ):
            raise GitHubLifecycleError("GitHub repository mapping is already bound.")
        _ensure_installation(connection, installation_id, tenant_id)
        now = _now()
        if existing:
            connection.execute(
                """UPDATE github_repository_bindings
                   SET installation_id = ?, repository_id = ?, state = 'active',
                       last_seen_at = ?, revoked_at = NULL
                   WHERE project_id = ?""",
                (installation_id, repository_id, now, project_id),
            )
        else:
            connection.execute(
                """INSERT INTO github_repository_bindings
                   (project_id, tenant_id, installation_id, repository_id,
                    repository_full_name, state, created_at, last_seen_at, revoked_at)
                   VALUES (?, ?, ?, ?, ?, 'active', ?, ?, NULL)""",
                (project_id, tenant_id, installation_id, repository_id, name, now, now),
            )
        route = _route_for_binding(connection, project_id)
        if not route:
            raise GitHubLifecycleError("GitHub repository binding could not be activated.")
        return _route_dict(route)


def resolve_github_webhook_binding(
    *, repository_full_name: str, repository_id: int, installation_id: int
) -> dict:
    """Resolve a signed webhook to exactly one active tenant-bound project."""
    name = _repository_name(repository_full_name)
    repository_id = _positive_id(repository_id, "repository ID")
    installation_id = _positive_id(installation_id, "installation ID")
    with get_connection() as connection:
        installation = connection.execute(
            "SELECT state FROM github_installations WHERE installation_id = ?",
            (installation_id,),
        ).fetchone()
        if installation and installation[0] != "active":
            raise GitHubLifecycleError("GitHub installation is revoked.")
        revoked_binding = connection.execute(
            """SELECT 1 FROM github_repository_bindings
               WHERE state = 'revoked' AND repository_id = ?
                 AND installation_id = ? AND repository_full_name = ?""",
            (repository_id, installation_id, name),
        ).fetchone()
        if revoked_binding:
            raise GitHubLifecycleError("GitHub repository mapping is revoked.")
        exact = connection.execute(
            """SELECT b.project_id, b.tenant_id, b.installation_id,
                      b.repository_id, b.repository_full_name, i.state
               FROM github_repository_bindings b
               JOIN github_installations i ON i.installation_id = b.installation_id
               WHERE b.state = 'active' AND b.repository_full_name = ?
                 AND b.repository_id = ? AND b.installation_id = ?""",
            (name, repository_id, installation_id),
        ).fetchall()
        if len(exact) == 1:
            route = _route_for_binding(connection, int(exact[0][0]))
            if not route:
                raise GitHubLifecycleError("GitHub project owner is inactive.")
            if exact[0][5] != "active":
                raise GitHubLifecycleError("GitHub installation is revoked.")
            connection.execute(
                "UPDATE github_repository_bindings SET last_seen_at = ? WHERE project_id = ?",
                (_now(), int(exact[0][0])),
            )
            return _route_dict(_route_for_binding(connection, int(exact[0][0])))
        if len(exact) > 1:
            raise GitHubLifecycleError("GitHub repository mapping is ambiguous.")

        active_identity = connection.execute(
            """SELECT project_id FROM github_repository_bindings
               WHERE state = 'active' AND repository_full_name = ?
                 AND (repository_id = ? OR installation_id = ?)""",
            (name, repository_id, installation_id),
        ).fetchall()
        if active_identity:
            raise GitHubLifecycleError("GitHub repository or installation does not match its binding.")

        legacy = connection.execute(
            """SELECT project_id, tenant_id FROM github_repository_bindings
               WHERE state = 'legacy' AND repository_full_name = ?""",
            (name,),
        ).fetchall()
        if len(legacy) > 1:
            raise GitHubLifecycleError("GitHub repository mapping is ambiguous.")
        if len(legacy) == 1:
            project_id, tenant_id = (int(value) for value in legacy[0])
            # This is the only promotion path: a unique legacy project is
            # paired with the exact signed repository and installation IDs.
            return _bind_github_repository_in_connection(
                connection,
                project_id=project_id,
                tenant_id=tenant_id,
                installation_id=installation_id,
                repository_id=repository_id,
                name=name,
            )
    raise GitHubLifecycleError("GitHub repository is not bound to an active tenant.")


def _bind_github_repository_in_connection(
    connection, *, project_id: int, tenant_id: int, installation_id: int, repository_id: int, name: str
) -> dict:
    """Promote a unique legacy row while retaining one transaction boundary."""
    if _active_conflict(connection, project_id=project_id, repository_id=repository_id, name=name):
        raise GitHubLifecycleError("GitHub repository mapping is ambiguous.")
    _ensure_installation(connection, installation_id, tenant_id)
    now = _now()
    connection.execute(
        """UPDATE github_repository_bindings
           SET installation_id = ?, repository_id = ?, state = 'active',
               last_seen_at = ?, revoked_at = NULL
           WHERE project_id = ? AND tenant_id = ? AND state = 'legacy'""",
        (installation_id, repository_id, now, project_id, tenant_id),
    )
    route = _route_for_binding(connection, project_id)
    if not route:
        raise GitHubLifecycleError("GitHub repository binding could not be activated.")
    return _route_dict(route)


def require_active_github_binding(
    *, tenant_id: int, installation_id: int, repository_full_name: str
) -> dict:
    """Return an active binding for worker/API use; never promote legacy data."""
    tenant_id = _positive_id(tenant_id, "tenant ID")
    installation_id = _positive_id(installation_id, "installation ID")
    name = _repository_name(repository_full_name)
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT b.project_id, b.tenant_id, b.installation_id,
                      b.repository_id, b.repository_full_name, i.state
               FROM github_repository_bindings b
               JOIN github_installations i ON i.installation_id = b.installation_id
               WHERE b.state = 'active' AND b.tenant_id = ?
                 AND b.installation_id = ? AND b.repository_full_name = ?""",
            (tenant_id, installation_id, name),
        ).fetchall()
        if len(rows) != 1:
            raise GitHubLifecycleError("GitHub repository is not bound to this tenant.")
        if rows[0][5] != "active":
            raise GitHubLifecycleError("GitHub installation is revoked.")
        route = _route_for_binding(connection, int(rows[0][0]))
        if not route:
            raise GitHubLifecycleError("GitHub project owner is inactive.")
        return _route_dict(route)


def github_oauth_capability_active(user_id: int) -> bool:
    with get_connection() as connection:
        row = connection.execute(
            """SELECT 1 FROM github_connections c
               JOIN auth_users u ON u.id = c.user_id
               WHERE c.user_id = ? AND u.active = 1 AND c.revoked_at IS NULL
                 AND c.token_encrypted <> ''""",
            (int(user_id),),
        ).fetchone()
    return bool(row)


def revoke_github_capabilities(
    *,
    user_id: int | None = None,
    tenant_id: int | None = None,
    installation_id: int | None = None,
    project_id: int | None = None,
) -> int:
    """Revoke OAuth, installation, and project capabilities through one API."""
    if all(value is None for value in (user_id, tenant_id, installation_id, project_id)):
        raise ValueError("A GitHub capability scope is required for revocation.")
    if tenant_id is not None:
        tenant_id = _positive_id(tenant_id, "tenant ID")
    now = _now()
    affected = 0
    with get_connection() as connection:
        if user_id is not None or tenant_id is not None:
            if user_id is not None:
                cursor = connection.execute(
                    """UPDATE github_connections
                       SET token_encrypted = '', scopes = '', revoked_at = ?
                       WHERE user_id = ?""",
                    (now, int(user_id)),
                )
            else:
                assert tenant_id is not None
                cursor = connection.execute(
                    """UPDATE github_connections
                       SET token_encrypted = '', scopes = '', revoked_at = ?
                       WHERE user_id IN (SELECT id FROM auth_users WHERE tenant_id = ?)""",
                    (now, int(tenant_id)),
                )
            affected += max(0, int(getattr(cursor, "rowcount", 0)))

        if installation_id is not None:
            installation_id = _positive_id(installation_id, "installation ID")
            cursor = connection.execute(
                """UPDATE github_installations
                   SET state = 'revoked', revoked_at = ?, last_seen_at = ?
                   WHERE installation_id = ? AND state <> 'revoked'""",
                (now, now, installation_id),
            )
            affected += max(0, int(getattr(cursor, "rowcount", 0)))
            cursor = connection.execute(
                """UPDATE github_repository_bindings
                   SET state = 'revoked', revoked_at = ?, last_seen_at = ?
                   WHERE installation_id = ? AND state = 'active'""",
                (now, now, installation_id),
            )
            affected += max(0, int(getattr(cursor, "rowcount", 0)))

        if tenant_id is not None:
            cursor = connection.execute(
                """UPDATE github_installations
                   SET state = 'revoked', revoked_at = ?, last_seen_at = ?
                   WHERE tenant_id = ? AND state <> 'revoked'""",
                (now, now, int(tenant_id)),
            )
            affected += max(0, int(getattr(cursor, "rowcount", 0)))
            cursor = connection.execute(
                """UPDATE github_repository_bindings
                   SET state = 'revoked', revoked_at = ?, last_seen_at = ?
                   WHERE tenant_id = ? AND state = 'active'""",
                (now, now, int(tenant_id)),
            )
            affected += max(0, int(getattr(cursor, "rowcount", 0)))

        if project_id is not None:
            project_id = _positive_id(project_id, "project ID")
            cursor = connection.execute(
                """UPDATE github_repository_bindings
                   SET state = 'revoked', revoked_at = ?, last_seen_at = ?
                   WHERE project_id = ? AND state = 'active'""",
                (now, now, project_id),
            )
            affected += max(0, int(getattr(cursor, "rowcount", 0)))
    return affected


def authorize_queued_scan(
    *,
    job_id: str,
    scan_run_id: int,
    project_id: int,
    requested_by: int,
    preset: str,
    source_revision: str | None,
    github_installation_id: int | None,
) -> dict:
    """Re-read and authorize a queued scan immediately before source access."""
    with get_connection() as connection:
        run = connection.execute(
            """SELECT job_id, project_id, requested_by, target, preset, state,
                      tenant_id, source_revision, github_installation_id
               FROM scan_runs WHERE id = ?""",
            (int(scan_run_id),),
        ).fetchone()
        if not run:
            raise GitHubLifecycleError("Queued scan metadata is missing.")
        if run[5] != "queued":
            raise GitHubLifecycleError("Queued scan is no longer claimable.")
        if (
            run[0] != job_id
            or int(run[1]) != int(project_id)
            or int(run[2]) != int(requested_by)
            or run[3] != "project"
            or run[4] != preset
            or run[7] != source_revision
            or (int(run[8]) if run[8] is not None else None)
            != (int(github_installation_id) if github_installation_id is not None else None)
        ):
            raise GitHubLifecycleError("Queued scan payload does not match its database record.")

        project = connection.execute(
            """SELECT id, tenant_id, created_by, repository_url, github_full_name
               FROM projects WHERE id = ?""",
            (int(project_id),),
        ).fetchone()
        requester = connection.execute(
            """SELECT active, tenant_id, role FROM auth_users WHERE id = ?""",
            (int(requested_by),),
        ).fetchone()
        if not project or not requester or not requester[0]:
            raise GitHubLifecycleError("Queued scan principal or project is unavailable.")
        if int(project[1]) != int(run[6]) or int(requester[1]) != int(run[6]):
            raise GitHubLifecycleError("Queued scan tenant authorization failed.")
        if requester[2] != "admin":
            member = connection.execute(
                """SELECT role FROM project_members
                   WHERE project_id = ? AND user_id = ?""",
                (int(project_id), int(requested_by)),
            ).fetchone()
            if not member or member[0] not in {"operator", "admin"}:
                raise GitHubLifecycleError("Queued scan project membership was revoked.")

        if project[3]:
            if github_installation_id is not None:
                name = _repository_name(project[4] or "")
                rows = connection.execute(
                    """SELECT b.project_id FROM github_repository_bindings b
                       JOIN github_installations i ON i.installation_id = b.installation_id
                       WHERE b.state = 'active' AND i.state = 'active'
                         AND b.project_id = ? AND b.tenant_id = ?
                         AND b.installation_id = ? AND b.repository_full_name = ?""",
                    (int(project_id), int(run[6]), int(github_installation_id), name),
                ).fetchall()
                if len(rows) != 1:
                    raise GitHubLifecycleError("Queued scan GitHub installation is revoked or unbound.")
            else:
                row = connection.execute(
                    """SELECT 1 FROM github_connections c
                       WHERE c.user_id = ? AND c.revoked_at IS NULL
                         AND c.token_encrypted <> ''""",
                    (int(requested_by),),
                ).fetchone()
                if not row:
                    raise GitHubLifecycleError("Queued scan GitHub credential is revoked or unavailable.")

        return {
            "tenant_id": int(run[6]),
            "project_id": int(project[0]),
            "requested_by": int(requested_by),
            "github_installation_id": (
                int(github_installation_id) if github_installation_id is not None else None
            ),
        }
