from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet

from app import database, github_integration, github_lifecycle, projects


def configure_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "github-lifecycle.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(github_integration, "get_connection", database.get_connection)
    monkeypatch.setattr(github_lifecycle, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "USING_POSTGRES", False)
    database.initialize_database(reset=True)


def add_user(connection, username: str, tenant_id: int, role: str = "operator") -> int:
    cursor = connection.execute(
        """INSERT INTO auth_users
           (username, password_hash, role, active, created_at, tenant_id)
           VALUES (?, 'unused', ?, 1, ?, ?)""",
        (username, role, datetime.now(timezone.utc).isoformat(), tenant_id),
    )
    return int(cursor.lastrowid)


def add_second_tenant(connection) -> int:
    cursor = connection.execute(
        """INSERT INTO tenants (slug, name, created_at)
           VALUES ('second', 'Second workspace', ?)""",
        (datetime.now(timezone.utc).isoformat(),),
    )
    return int(cursor.lastrowid)


def test_unique_legacy_backfill_promotes_and_active_mapping_is_immutable(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "github-owner", tenant_id)

    project_id = projects.create_project(
        name="API",
        repository_url="https://github.com/example/api.git",
        github_full_name="example/api",
        default_branch="main",
        scan_preset="quick",
        user_id=user_id,
        tenant_id=tenant_id,
    )

    with database.get_connection() as connection:
        legacy = connection.execute(
            """SELECT state, installation_id, repository_id
               FROM github_repository_bindings WHERE project_id = ?""",
            (project_id,),
        ).fetchone()
    assert tuple(legacy) == ("legacy", None, None)

    route = github_lifecycle.resolve_github_webhook_binding(
        repository_full_name="example/api",
        repository_id=101,
        installation_id=202,
    )
    assert route["project_id"] == project_id
    assert route["tenant_id"] == tenant_id

    with pytest.raises(github_lifecycle.GitHubLifecycleError, match="immutable"):
        github_lifecycle.bind_github_repository(
            project_id=project_id,
            tenant_id=tenant_id,
            installation_id=203,
            repository_id=101,
            repository_full_name="example/api",
        )
    with database.get_connection() as connection:
        with pytest.raises(Exception, match="immutable"):
            connection.execute(
                "UPDATE github_repository_bindings SET installation_id = 203 WHERE project_id = ?",
                (project_id,),
            )


def test_duplicate_legacy_repository_names_fail_closed_across_tenants(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_one = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        tenant_two = add_second_tenant(connection)
        user_one = add_user(connection, "one", tenant_one)
        user_two = add_user(connection, "two", tenant_two)

    for user_id, tenant_id in ((user_one, tenant_one), (user_two, tenant_two)):
        projects.create_project(
            name=f"API {tenant_id}",
            repository_url="https://github.com/example/api.git",
            github_full_name="example/api",
            default_branch="main",
            scan_preset="quick",
            user_id=user_id,
            tenant_id=tenant_id,
        )

    with pytest.raises(github_lifecycle.GitHubLifecycleError, match="ambiguous"):
        github_lifecycle.resolve_github_webhook_binding(
            repository_full_name="example/api",
            repository_id=101,
            installation_id=202,
        )


def test_capability_revocation_invalidates_oauth_and_app_queued_access(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    encryption_key = Fernet.generate_key()
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", encryption_key.decode())
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "queue-owner", tenant_id)

    project_id = projects.create_project(
        name="Queued API",
        repository_url="https://github.com/example/api.git",
        github_full_name="example/api",
        default_branch="main",
        scan_preset="quick",
        user_id=user_id,
        tenant_id=tenant_id,
    )
    with database.get_connection() as connection:
        connection.execute(
            """INSERT INTO github_connections
               (user_id, github_login, token_encrypted, scopes, connected_at)
               VALUES (?, 'queue-owner', ?, 'repo', ?)""",
            (
                user_id,
                Fernet(encryption_key).encrypt(b"oauth-token").decode(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    run_id = projects.create_scan_run(
        job_id="queued-oauth",
        project_id=project_id,
        requested_by=user_id,
        target="project",
        preset="quick",
    )
    assert github_integration.github_token(user_id) == "oauth-token"
    github_lifecycle.authorize_queued_scan(
        job_id="queued-oauth",
        scan_run_id=run_id,
        project_id=project_id,
        requested_by=user_id,
        preset="quick",
        source_revision=None,
        github_installation_id=None,
    )

    github_lifecycle.revoke_github_capabilities(user_id=user_id)
    assert github_integration.github_token(user_id) is None
    with pytest.raises(github_lifecycle.GitHubLifecycleError, match="credential"):
        github_lifecycle.authorize_queued_scan(
            job_id="queued-oauth",
            scan_run_id=run_id,
            project_id=project_id,
            requested_by=user_id,
            preset="quick",
            source_revision=None,
            github_installation_id=None,
        )

    github_lifecycle.bind_github_repository(
        project_id=project_id,
        tenant_id=tenant_id,
        installation_id=202,
        repository_id=101,
        repository_full_name="example/api",
    )
    github_lifecycle.revoke_github_capabilities(installation_id=202)
    with pytest.raises(github_lifecycle.GitHubLifecycleError, match="revoked"):
        github_lifecycle.resolve_github_webhook_binding(
            repository_full_name="example/api",
            repository_id=101,
            installation_id=202,
        )


def test_queued_scan_recheck_rejects_tampered_payload_and_unbound_installation(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "scan-owner", tenant_id)
    project_id = projects.create_project(
        name="Bound API",
        repository_url="https://github.com/example/api.git",
        github_full_name="example/api",
        default_branch="main",
        scan_preset="quick",
        user_id=user_id,
        tenant_id=tenant_id,
    )
    github_lifecycle.bind_github_repository(
        project_id=project_id,
        tenant_id=tenant_id,
        installation_id=202,
        repository_id=101,
        repository_full_name="example/api",
    )
    run_id = projects.create_scan_run(
        job_id="queued-app",
        project_id=project_id,
        requested_by=user_id,
        target="project",
        preset="quick",
        github_installation_id=202,
    )

    with pytest.raises(Exception, match="not tenant-bound"):
        projects.create_scan_run(
            job_id="unbound-app",
            project_id=project_id,
            requested_by=user_id,
            target="project",
            preset="quick",
            github_installation_id=999,
        )

    github_lifecycle.authorize_queued_scan(
        job_id="queued-app",
        scan_run_id=run_id,
        project_id=project_id,
        requested_by=user_id,
        preset="quick",
        source_revision=None,
        github_installation_id=202,
    )
    with pytest.raises(github_lifecycle.GitHubLifecycleError, match="payload"):
        github_lifecycle.authorize_queued_scan(
            job_id="queued-app",
            scan_run_id=run_id,
            project_id=project_id,
            requested_by=user_id,
            preset="quick",
            source_revision=None,
            github_installation_id=999,
        )

    with database.get_connection() as connection:
        connection.execute(
            "UPDATE project_members SET role = 'viewer' WHERE project_id = ? AND user_id = ?",
            (project_id, user_id),
        )
    with pytest.raises(github_lifecycle.GitHubLifecycleError, match="membership"):
        github_lifecycle.authorize_queued_scan(
            job_id="queued-app",
            scan_run_id=run_id,
            project_id=project_id,
            requested_by=user_id,
            preset="quick",
            source_revision=None,
            github_installation_id=202,
        )
