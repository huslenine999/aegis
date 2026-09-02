import hashlib
import hmac
import json
import time
import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import (
    audit,
    auth,
    cli,
    config,
    database,
    github_integration,
    github_lifecycle,
    projects,
    worker,
)
from app.artifact_storage import run_directory
from app.evidence import sign_manifest, verify_manifest
from app.notifier_entrypoint import validate_notifier_configuration
from app.worker_entrypoint import validate_worker_configuration


def configure_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "hardening.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(auth, "get_connection", database.get_connection)
    monkeypatch.setattr(audit, "get_connection", database.get_connection)
    monkeypatch.setattr(github_integration, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "USING_POSTGRES", False)
    database.initialize_database(reset=True)


def add_user(connection, username: str, role: str, tenant_id: int, user_id=None):
    values = (
        username,
        auth.hash_password("correct horse battery staple"),
        role,
        datetime.now(timezone.utc).isoformat(),
        tenant_id,
    )
    if user_id is None:
        cursor = connection.execute(
            """INSERT INTO auth_users
               (username, password_hash, role, active, created_at, tenant_id)
               VALUES (?, ?, ?, 1, ?, ?)""",
            values,
        )
        return int(cursor.lastrowid)
    connection.execute(
        """INSERT INTO auth_users
           (id, username, password_hash, role, active, created_at, tenant_id)
           VALUES (?, ?, ?, ?, 1, ?, ?)""",
        (user_id, *values),
    )
    return user_id


def test_tenant_admin_cannot_enumerate_or_share_other_tenant_projects(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_one = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        cursor = connection.execute(
            """INSERT INTO tenants (slug, name, created_at)
               VALUES ('other', 'Other', ?)""",
            (datetime.now(timezone.utc).isoformat(),),
        )
        tenant_two = int(cursor.lastrowid)
        admin_one = add_user(connection, "tenant-one-admin", "admin", tenant_one)
        admin_two = add_user(connection, "tenant-two-admin", "admin", tenant_two)

    first = projects.create_project(
        name="First",
        repository_url="",
        github_full_name="",
        default_branch="main",
        scan_preset="quick",
        user_id=admin_one,
        tenant_id=tenant_one,
    )
    second = projects.create_project(
        name="Second",
        repository_url="",
        github_full_name="",
        default_branch="main",
        scan_preset="quick",
        user_id=admin_two,
        tenant_id=tenant_two,
    )

    assert [item["id"] for item in projects.list_projects(admin_one, "admin", tenant_one)] == [first]
    assert projects.get_project(second, tenant_one) is None
    assert projects.project_role(second, admin_one, "admin", tenant_one) is None
    run_id = projects.create_scan_run(
        job_id="tenant-guard-run",
        project_id=first,
        requested_by=admin_one,
        target="project",
        preset="quick",
    )
    with pytest.raises(ValueError, match="Active user not found"):
        projects.set_project_member(first, "tenant-two-admin", "viewer")
    with database.get_connection() as connection:
        with pytest.raises(Exception, match="tenant mismatch"):
            connection.execute(
                """INSERT INTO project_members
                   (project_id, user_id, role, created_at) VALUES (?, ?, 'viewer', ?)""",
                (first, admin_two, datetime.now(timezone.utc).isoformat()),
            )
        with pytest.raises(Exception, match="immutable"):
            connection.execute(
                "UPDATE auth_users SET tenant_id = ? WHERE id = ?",
                (tenant_two, admin_one),
            )
        with pytest.raises(Exception, match="tenant mismatch"):
            connection.execute(
                "UPDATE scan_runs SET requested_by = ? WHERE id = ?",
                (admin_two, run_id),
            )
        with pytest.raises(Exception, match="tenant mismatch"):
            connection.execute(
                "UPDATE project_members SET user_id = ? WHERE project_id = ? AND user_id = ?",
                (admin_two, first, admin_one),
            )


def test_api_tokens_are_keyed_scoped_and_track_last_use(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "automation-user", "operator", tenant_id)
        token = "aegis-test-token"
        connection.execute(
            """INSERT INTO auth_tokens
               (user_id, token_hash, hash_scheme, revoked_at, name,
                expires_at, created_at, scopes)
               VALUES (?, ?, ?, NULL, 'read-only', NULL, ?, 'read')""",
            (
                user_id,
                auth.hash_api_token(token),
                auth.API_TOKEN_HASH_SCHEME,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    principal = auth._api_token_principal(token)

    assert principal is not None
    assert principal.tenant_id == tenant_id
    assert principal.scopes == ("read",)
    assert principal.auth_method == "token"
    assert auth._scope_allows(principal.scopes, "read")
    assert not auth._scope_allows(principal.scopes, "write")
    with database.get_connection() as connection:
        assert connection.execute(
            "SELECT last_used_at FROM auth_tokens WHERE user_id = ?", (user_id,)
        ).fetchone()[0]


def test_legacy_api_token_rows_are_rejected_and_versioned_tokens_work(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "legacy-token-user", "operator", tenant_id)
        legacy_token = "legacy-unsalted-token"
        current_token = "current-keyed-token"
        now = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """INSERT INTO auth_tokens
               (user_id, token_hash, name, expires_at, created_at, scopes)
               VALUES (?, ?, 'legacy', NULL, ?, 'read')""",
            (user_id, hashlib.sha256(legacy_token.encode()).hexdigest(), now),
        )
        connection.execute(
            """INSERT INTO auth_tokens
               (user_id, token_hash, hash_scheme, revoked_at, name,
                expires_at, created_at, scopes)
               VALUES (?, ?, ?, NULL, 'current', NULL, ?, 'read')""",
            (
                user_id,
                auth.hash_api_token(current_token),
                auth.API_TOKEN_HASH_SCHEME,
                now,
            ),
        )

    assert auth._api_token_principal(legacy_token) is None
    principal = auth._api_token_principal(current_token)
    assert principal is not None
    assert principal.username == "legacy-token-user"


def test_static_admin_token_is_not_an_api_authentication_path(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_ADMIN_TOKEN", "static-admin-token-for-tests")
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        add_user(connection, "static-admin-user", "admin", tenant_id)

    assert auth._api_token_principal("static-admin-token-for-tests") is None


def test_api_token_migration_revokes_unclassified_rows(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "migration-token-user", "operator", tenant_id)
        connection.execute(
            """INSERT INTO auth_tokens
               (user_id, token_hash, hash_scheme, revoked_at, name,
                expires_at, created_at, scopes)
               VALUES (?, ?, 'legacy', NULL, 'legacy', NULL, ?, 'read')""",
            (
                user_id,
                hashlib.sha256(b"legacy-migration-token").hexdigest(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        database._migration_020_api_token_hash_version(connection.cursor())

        revoked_at = connection.execute(
            "SELECT revoked_at FROM auth_tokens WHERE user_id = ?", (user_id,)
        ).fetchone()[0]

    assert revoked_at


def test_login_lockout_blocks_a_correct_password_until_expiry(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    monkeypatch.setattr(auth, "LOGIN_FAILURE_LIMIT", 3)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "lockout-user", "viewer", tenant_id)

    for _ in range(3):
        assert auth.authenticate("lockout-user", "wrong password") is None
    assert auth.authenticate("lockout-user", "correct horse battery staple") is None

    with database.get_connection() as connection:
        connection.execute(
            "UPDATE auth_users SET locked_until = ? WHERE id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), user_id),
        )
    assert auth.authenticate("lockout-user", "correct horse battery staple") is not None


def test_totp_mfa_and_recovery_codes_are_encrypted_and_single_use(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "mfa-user", "admin", tenant_id)

    setup = auth.begin_mfa_setup(user_id, "mfa-user")
    recovery_codes = auth.confirm_mfa_setup(user_id, auth._totp(setup["secret"]))

    assert auth.authenticate("mfa-user", "correct horse battery staple") is None
    next_code = auth._totp(setup["secret"], int(time.time()) + 30)
    assert auth.authenticate(
        "mfa-user",
        "correct horse battery staple",
        next_code,
    ) is not None
    assert auth.authenticate(
        "mfa-user", "correct horse battery staple", next_code
    ) is None
    assert auth.authenticate(
        "mfa-user", "correct horse battery staple", recovery_codes[0]
    ) is not None
    assert auth.authenticate(
        "mfa-user", "correct horse battery staple", recovery_codes[0]
    ) is None
    with database.get_connection() as connection:
        row = connection.execute(
            "SELECT mfa_secret_encrypted FROM auth_users WHERE id = ?", (user_id,)
        ).fetchone()
    assert setup["secret"] not in row[0]


def test_mfa_recovery_consumption_uses_compare_and_swap(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "mfa-cas-user", "admin", tenant_id)

    setup = auth.begin_mfa_setup(user_id, "mfa-cas-user")
    recovery_codes = auth.confirm_mfa_setup(user_id, auth._totp(setup["secret"]))
    with database.get_connection() as connection:
        row = connection.execute(
            """SELECT mfa_secret_encrypted, mfa_recovery_hashes
               FROM auth_users WHERE id = ?""",
            (user_id,),
        ).fetchone()
        stale_recovery_json = row[1]
        assert auth._consume_second_factor(
            connection, user_id, recovery_codes[0], row[0], stale_recovery_json
        )
        assert not auth._consume_second_factor(
            connection, user_id, recovery_codes[0], row[0], stale_recovery_json
        )


def test_signed_evidence_detects_manifest_tampering():
    manifest = sign_manifest(
        {
            "schema_version": 2,
            "source": {"identity": "example/api", "revision": "a" * 40},
            "policy_status": "PASS",
        }
    )

    public_key = manifest["signature"]["public_key"]
    assert not verify_manifest(manifest)
    assert verify_manifest(manifest, public_key)
    manifest["policy_status"] = "BLOCKED"
    assert not verify_manifest(manifest, public_key)


def test_cli_verifies_signed_manifest_and_artifact_hashes(tmp_path):
    report = tmp_path / "report.md"
    report.write_text("verified evidence\n")
    manifest = sign_manifest(
        {
            "schema_version": 2,
            "artifacts": [
                {
                    "name": report.name,
                    "size": report.stat().st_size,
                    "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                }
            ],
        }
    )
    manifest_path = tmp_path / "scan-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    public_key = manifest["signature"]["public_key"]
    assert cli.run_verify_evidence(str(manifest_path)) == 2
    assert cli.run_verify_evidence(str(manifest_path), public_key) == 0
    report.write_text("tampered\n")
    assert cli.run_verify_evidence(str(manifest_path)) == 2


def test_github_webhooks_verify_signature_and_reject_replay(
    tmp_path, monkeypatch
):
    configure_database(tmp_path, monkeypatch)
    secret = "w" * 40
    monkeypatch.setenv("AEGIS_GITHUB_WEBHOOK_SECRET", secret)
    body = json.dumps(
        {"action": "synchronize", "repository": {"full_name": "example/api"}},
        separators=(",", ":"),
    ).encode()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    arguments = {
        "signature_header": signature,
        "delivery_id": "12345678-abcd-1234-abcd-123456789012",
        "event_type": "pull_request",
    }

    delivery = github_integration.verify_and_record_webhook(body, **arguments)

    assert delivery["repository"] == "example/api"
    with pytest.raises(ValueError, match="already been processed"):
        github_integration.verify_and_record_webhook(body, **arguments)


def test_artifact_paths_are_tenant_scoped_and_reject_unsafe_job_ids(tmp_path):
    path = run_directory(
        tmp_path, "safe-job", tenant_id=7, project_id=9, create=True
    )

    assert path == tmp_path / "tenants" / "7" / "projects" / "9" / "runs" / "safe-job"
    with pytest.raises(ValueError, match="Invalid scan job"):
        run_directory(tmp_path, "../escape", tenant_id=7, project_id=9, create=True)


def test_worker_fails_startup_for_invalid_signing_or_isolation_configuration(
    monkeypatch,
):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setenv("AEGIS_EVIDENCE_SIGNING_KEY", "not-a-key")
    with pytest.raises(RuntimeError, match="AEGIS_EVIDENCE_SIGNING_KEY"):
        validate_worker_configuration()

    monkeypatch.setenv(
        "AEGIS_EVIDENCE_SIGNING_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    monkeypatch.setenv("AEGIS_ALLOW_DEEP_SCANS", "true")
    monkeypatch.setenv("AEGIS_ISOLATED_WORKER", "false")
    with pytest.raises(RuntimeError, match="AEGIS_ISOLATED_WORKER"):
        validate_worker_configuration()

    monkeypatch.setenv("AEGIS_ALLOW_DEEP_SCANS", "false")
    monkeypatch.setenv("AEGIS_ENABLE_SAFETY", "true")
    monkeypatch.delenv("SAFETY_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SAFETY_API_KEY"):
        validate_worker_configuration()


def test_production_workers_reject_cross_boundary_secrets(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setenv(
        "AEGIS_EVIDENCE_SIGNING_KEY",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    monkeypatch.setenv("AEGIS_SESSION_SECRET", "must-not-reach-scanner")
    with pytest.raises(RuntimeError, match="AEGIS_SESSION_SECRET"):
        validate_worker_configuration()

    monkeypatch.delenv("AEGIS_SESSION_SECRET")
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("AEGIS_EVIDENCE_SIGNING_KEY", "must-not-reach-notifier")
    with pytest.raises(RuntimeError, match="AEGIS_EVIDENCE_SIGNING_KEY"):
        validate_notifier_configuration()


def test_s3_artifact_backend_requires_a_bucket(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "development")
    monkeypatch.setenv("AEGIS_ARTIFACT_BACKEND", "s3")
    monkeypatch.delenv("AEGIS_S3_BUCKET", raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_S3_BUCKET is required"):
        config.validate_runtime_configuration()

    monkeypatch.setenv("AEGIS_S3_BUCKET", "aegis-evidence")
    config.validate_runtime_configuration()


def test_recent_authentication_can_be_refreshed(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "step-up-user", "admin", tenant_id)
    principal = auth.authenticate("step-up-user", "correct horse battery staple")
    assert principal is not None
    token = auth.create_session(principal)
    assert auth.session_authentication_is_recent(token)
    with database.get_connection() as connection:
        connection.execute(
            "UPDATE auth_sessions SET authenticated_at = ? WHERE user_id = ?",
            ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), user_id),
        )
    assert not auth.session_authentication_is_recent(token)
    assert auth.reauthenticate_session(
        token, principal, "correct horse battery staple"
    )
    assert auth.session_authentication_is_recent(token)


def test_audit_chain_is_append_only_and_verifiable(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    monkeypatch.setenv("AEGIS_AUDIT_HMAC_KEY", "a" * 40)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "auditor", "admin", tenant_id)

    first = audit.record_audit(user_id, "project.created", "project", 1)
    second = audit.record_audit(user_id, "project.updated", "project", 1)
    result = audit.verify_audit_chain(tenant_id)

    assert first and second and first != second
    assert result == {"valid": True, "events": 2, "head_hash": second}
    with database.get_connection() as connection:
        with pytest.raises(Exception, match="append-only"):
            connection.execute("DELETE FROM audit_events WHERE tenant_id = ?", (tenant_id,))


def test_audit_key_fails_closed_in_production_without_hmac_key(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_AUDIT_HMAC_KEY", raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_AUDIT_HMAC_KEY"):
        audit._audit_key()


def test_bank_security_profile_fails_closed(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setenv("AEGIS_SECURITY_PROFILE", "bank")
    with pytest.raises(RuntimeError, match="fail-closed"):
        config.validate_runtime_configuration()


def test_github_app_uses_signed_jwt_installation_token_and_check_run(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv("AEGIS_GITHUB_APP_ID", "12345")
    monkeypatch.setenv(
        "AEGIS_GITHUB_APP_PRIVATE_KEY_B64", base64.b64encode(pem).decode()
    )
    monkeypatch.setenv("AEGIS_GITHUB_WEBHOOK_SECRET", "w" * 40)

    encoded_header, encoded_claims, encoded_signature = (
        github_integration.github_app_jwt().split(".")
    )
    signing_input = f"{encoded_header}.{encoded_claims}".encode()
    signature = base64.urlsafe_b64decode(encoded_signature + "==")
    private_key.public_key().verify(
        signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
    )
    claims = json.loads(
        base64.urlsafe_b64decode(encoded_claims + "==").decode()
    )
    assert claims["iss"] == "12345"
    assert claims["exp"] - claims["iat"] == 600

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    monkeypatch.setattr(
        github_integration.requests,
        "post",
        lambda *args, **kwargs: Response({"token": "ghs_installation_token"}),
    )
    captured = {}

    def request(method, url, **kwargs):
        captured.update({"method": method, "url": url, "json": kwargs["json"]})
        return Response({"id": 77})

    monkeypatch.setattr(github_integration.requests, "request", request)
    check_id = github_integration.create_check_run(
        9, "example/api", "a" * 40, "https://aegis.example.com/projects"
    )

    assert check_id == 77
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/repos/example/api/check-runs")
    assert captured["json"]["head_sha"] == "a" * 40

    github_integration.complete_check_run(
        9,
        "example/api",
        check_id,
        conclusion="failure",
        title="Blocked",
        summary="One finding",
        annotations=[{
            "path": "app/main.py",
            "start_line": 4,
            "end_line": 4,
            "annotation_level": "failure",
            "message": "Potential secret",
            "title": "Secret",
        }] * 51,
    )
    assert captured["method"] == "PATCH"
    assert len(captured["json"]["output"]["annotations"]) == 50


def test_github_annotations_are_repository_relative_and_line_addressable(tmp_path):
    repository = tmp_path / "repository"
    source = repository / "app" / "main.py"
    source.parent.mkdir(parents=True)
    source.write_text("print('safe')\n")

    annotations = worker._github_check_annotations({
        "ruff": [{
            "filename": str(source),
            "code": "S105",
            "message": "Possible hardcoded password",
            "location": {"row": 7},
        }],
        "semgrep": {"results": [{
            "path": "app/main.py",
            "check_id": "aegis.command-injection",
            "start": {"line": 8},
            "extra": {"message": "Unsafe command", "severity": "ERROR"},
        }]},
        "iac": {"findings": [{
            "path": "app/main.py",
            "start_line": 9,
            "end_line": 11,
            "rule_id": "CKV_TF_1",
            "title": "IaC configuration issue",
            "severity": "HIGH",
        }], "unmanaged_suppressions": [{
            "path": "app/main.py",
            "start_line": 12,
            "end_line": 12,
            "rule_id": "CKV_TF_2",
            "title": "Inline Checkov suppression",
            "source": "repository-inline-checkov",
        }]},
        "secrets": {"results": {"../outside.txt": [{
            "type": "Secret Keyword",
            "line_number": 1,
        }]}},
    }, repository)

    assert [item["path"] for item in annotations] == ["app/main.py"] * 4
    assert [item["start_line"] for item in annotations] == [7, 8, 9, 12]
    assert annotations[2]["end_line"] == 11
    assert annotations[1]["annotation_level"] == "failure"
    assert annotations[3]["annotation_level"] == "warning"


def test_scan_run_persists_github_pull_request_context(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    with database.get_connection() as connection:
        tenant_id = int(connection.execute("SELECT id FROM tenants").fetchone()[0])
        user_id = add_user(connection, "github-owner", "operator", tenant_id)
    project_id = projects.create_project(
        name="GitHub API",
        repository_url="https://github.com/example/api.git",
        github_full_name="example/api",
        default_branch="main",
        scan_preset="standard",
        user_id=user_id,
        tenant_id=tenant_id,
    )
    github_lifecycle.bind_github_repository(
        project_id=project_id,
        tenant_id=tenant_id,
        installation_id=42,
        repository_id=101,
        repository_full_name="example/api",
    )
    run_id = projects.create_scan_run(
        job_id="github-pr-run",
        project_id=project_id,
        requested_by=user_id,
        target="project",
        preset="standard",
        source_revision="b" * 40,
        source_ref="feature/security",
        github_installation_id=42,
        github_pull_request=17,
        github_check_run_id=88,
    )

    run = projects.get_scan_run(run_id, tenant_id)
    assert run["source_revision"] == "b" * 40
    assert run["github_installation_id"] == 42
    assert run["github_pull_request"] == 17
    assert run["github_check_run_id"] == 88
