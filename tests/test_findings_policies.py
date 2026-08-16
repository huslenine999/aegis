from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
import hashlib
import sys

import pytest
from cryptography.fernet import Fernet

from app import artifact_storage, database, findings, oidc, policies, projects, reporting


def configure_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "aegis.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    for module in (projects, findings, policies):
        monkeypatch.setattr(module, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "USING_POSTGRES", False)
    monkeypatch.setattr(policies, "USING_POSTGRES", False)
    monkeypatch.setattr(findings, "USING_POSTGRES", False)
    database.initialize_database(reset=True)
    with database.get_connection() as connection:
        connection.executemany(
            """INSERT INTO auth_users
               (id, tenant_id, username, password_hash, role, active, created_at)
               VALUES (?, 1, ?, 'unused', ?, 1, ?)""",
            [
                (10, "owner", "operator", "2026-01-01T00:00:00+00:00"),
                (11, "member", "operator", "2026-01-01T00:00:00+00:00"),
            ],
        )
    project_id = projects.create_project(
        name="API",
        repository_url="",
        github_full_name="",
        default_branch="main",
        scan_preset="standard",
        user_id=10,
    )
    projects.set_project_member(project_id, "member", "operator")
    return project_id


def create_run(project_id: int, job_id: str) -> int:
    return projects.create_scan_run(
        job_id=job_id,
        project_id=project_id,
        requested_by=10,
        target="project",
        preset="standard",
    )


def ruff_result(path: str = "src/app.py") -> dict:
    return {
        "ruff": [
            {
                "code": "S307",
                "message": "Use of eval",
                "filename": path,
                "location": {"row": 12},
            }
        ]
    }


def test_findings_are_idempotent_resolved_and_reopened(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    first = create_run(project_id, "first")

    initial = findings.sync_findings(first, ruff_result())
    repeated = findings.sync_findings(first, ruff_result())

    assert initial == {"observed": 1, "created": 1, "reopened": 0, "resolved": 0}
    assert repeated["created"] == 0
    assert findings.list_findings(project_id)[0]["occurrence_count"] == 1

    second = create_run(project_id, "second")
    assert findings.sync_findings(second, {})["resolved"] == 1
    assert findings.list_findings(project_id)[0]["status"] == "resolved"

    third = create_run(project_id, "third")
    assert findings.sync_findings(third, ruff_result())["reopened"] == 1
    reopened = findings.list_findings(project_id)[0]
    assert reopened["status"] == "open"
    assert reopened["occurrence_count"] == 2


def test_finding_lifecycle_requires_expiring_accepted_risk(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    run_id = create_run(project_id, "lifecycle")
    findings.sync_findings(run_id, ruff_result())
    finding_id = findings.list_findings(project_id)[0]["id"]

    with pytest.raises(ValueError, match="meaningful note"):
        findings.update_finding(
            project_id, finding_id, 10, {"status": "accepted", "resolution_note": "ok"}
        )
    with pytest.raises(ValueError, match="expiration"):
        findings.update_finding(
            project_id,
            finding_id,
            10,
            {"status": "accepted", "resolution_note": "Approved for this release."},
        )

    expiry = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    updated = findings.update_finding(
        project_id,
        finding_id,
        10,
        {
            "status": "accepted",
            "resolution_note": "Approved for this release.",
            "accepted_until": expiry,
            "owner_id": 11,
        },
    )
    assert updated["status"] == "accepted"
    assert updated["owner"] == "member"
    assert updated["events"][-1]["event_type"] == "status_changed"


def test_approved_policy_is_bound_to_scan_and_can_be_simulated(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    default = policies.ensure_active_policy(project_id, 10)
    run_id = projects.create_scan_run(
        job_id="policy-run",
        project_id=project_id,
        requested_by=10,
        target="project",
        preset="standard",
        policy_version_id=default["id"],
    )
    assert projects.get_scan_run(run_id)["policy_version_id"] == default["id"]

    projects.update_scan_run(
        run_id,
        state="completed",
        progress=100,
        result={**ruff_result(), "tools": [{"name": "Ruff", "status": "completed"}]},
    )
    simulation = policies.simulate_policy(
        project_id,
        run_id,
        {"schema_version": 1, "fail_on_severities": ["HIGH"], "required_tools": ["Ruff"]},
    )
    assert simulation["status"] == "BLOCKED"
    assert simulation["blocking_findings"] == 1

    draft = policies.create_policy(
        project_id,
        10,
        "Critical only",
        {"schema_version": 1, "fail_on_severities": ["CRITICAL"], "required_tools": []},
    )
    approved = policies.approve_policy(project_id, draft["id"], 10)
    assert approved["state"] == "approved"
    assert policies.get_policy(default["id"])["state"] == "retired"
    assert projects.get_scan_run(run_id)["policy_version_id"] == default["id"]


def test_s3_artifact_store_uses_encryption_lock_and_integrity_metadata(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text('{"status":"ok"}')
    calls = {}

    class Client:
        def upload_file(self, filename, bucket, key, ExtraArgs):
            calls.update(filename=filename, bucket=bucket, key=key, extra=ExtraArgs)

        def get_object(self, **kwargs):
            return {"Body": path.open("rb")}

    monkeypatch.setenv("AEGIS_S3_BUCKET", "evidence")
    monkeypatch.setenv("AEGIS_S3_KMS_KEY_ID", "kms-key")
    monkeypatch.setenv("AEGIS_S3_OBJECT_LOCK_DAYS", "30")
    store = artifact_storage.S3ArtifactStore(Client())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    store.put(path, "tenant/run/report.json", digest)

    assert calls["bucket"] == "evidence"
    assert calls["extra"]["ServerSideEncryption"] == "aws:kms"
    assert calls["extra"]["SSEKMSKeyId"] == "kms-key"
    assert calls["extra"]["ObjectLockMode"] == "GOVERNANCE"
    assert store.verify("tenant/run/report.json", path.stat().st_size, digest)


def test_oidc_pkce_state_and_verified_identity_provisioning(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    monkeypatch.setattr(oidc, "get_connection", database.get_connection)
    monkeypatch.setattr(oidc, "USING_POSTGRES", False)
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://identity.example")
    monkeypatch.setenv("AEGIS_OIDC_CLIENT_ID", "aegis-client")
    monkeypatch.setenv("AEGIS_OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setenv("AEGIS_OIDC_AUTO_PROVISION", "true")
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    metadata = {
        "issuer": "https://identity.example",
        "authorization_endpoint": "https://identity.example/authorize",
        "token_endpoint": "https://identity.example/token",
        "jwks_uri": "https://identity.example/keys",
        "id_token_signing_alg_values_supported": ["RS256", "none"],
    }

    class Response:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    def fake_get(url, **kwargs):
        del kwargs
        return Response(
            {"keys": [{"kid": "key-1", "kty": "RSA"}]}
            if url.endswith("/keys")
            else metadata
        )

    monkeypatch.setattr(oidc.requests, "get", fake_get)
    browser_binding = oidc.new_browser_binding()
    authorization_url = oidc.begin_oidc(
        "https://aegis.example/callback",
        "/projects",
        browser_binding=browser_binding,
    )
    query = parse_qs(urlparse(authorization_url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["nonce"]

    monkeypatch.setattr(
        oidc.requests,
        "post",
        lambda *args, **kwargs: Response({"id_token": "signed-token"}),
    )
    decoded = {}

    class KeySet:
        def __getitem__(self, key_id):
            assert key_id == "key-1"
            return SimpleNamespace(algorithm_name="RS256", key="public-key")

        def __iter__(self):
            return iter([self["key-1"]])

    class PyJWKSet:
        @staticmethod
        def from_dict(payload):
            assert payload["keys"]
            return KeySet()

    def decode(token, key, **kwargs):
        decoded.update(kwargs)
        return {
            "sub": "employee-42",
            "preferred_username": "employee@example.com",
            "nonce": query["nonce"][0],
        }

    monkeypatch.setitem(
        sys.modules,
        "jwt",
        SimpleNamespace(
            PyJWKSet=PyJWKSet,
            get_unverified_header=lambda token: {"alg": "RS256", "kid": "key-1"},
            decode=decode,
        ),
    )
    principal, return_to = oidc.complete_oidc(
        "code",
        query["state"][0],
        "https://aegis.example/callback",
        browser_binding=browser_binding,
    )

    assert principal.username == "employee@example.com"
    assert principal.role == "viewer"
    assert return_to == "/projects"
    assert decoded["issuer"] == "https://identity.example"
    assert decoded["audience"] == "aegis-client"
    assert decoded["algorithms"] == ["RS256"]


def test_oidc_rejects_unknown_state_before_discovery_io(tmp_path, monkeypatch):
    configure_database(tmp_path, monkeypatch)
    monkeypatch.setattr(oidc, "get_connection", database.get_connection)
    monkeypatch.setattr(oidc, "USING_POSTGRES", False)
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://identity.example")
    monkeypatch.setenv("AEGIS_OIDC_CLIENT_ID", "aegis-client")

    def unexpected_discovery(*args, **kwargs):
        raise AssertionError("OIDC discovery must not run for an invalid state")

    monkeypatch.setattr(oidc.requests, "get", unexpected_discovery)

    with pytest.raises(ValueError, match="invalid or expired"):
        oidc.complete_oidc("code", "unknown-state", "https://aegis.example/callback")


def test_artifact_limits_reject_oversized_files_and_bundles(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_MAX_ARTIFACT_BYTES", "8")
    monkeypatch.setenv("AEGIS_MAX_TOTAL_ARTIFACT_BYTES", "12")
    monkeypatch.setenv("AEGIS_MAX_REPORT_BUNDLE_BYTES", "64")
    oversized = tmp_path / "report.html"
    oversized.write_text("123456789")

    with pytest.raises(artifact_storage.ArtifactLimitError, match="per-artifact"):
        artifact_storage.publish_artifacts(
            tmp_path,
            {"report.html"},
            tenant_id=1,
            project_id=2,
            job_id="job-1",
        )

    with pytest.raises(artifact_storage.ArtifactLimitError, match="total"):
        artifact_storage.validate_artifact_sizes(
            [("one", 7), ("two", 6)]
        )

    monkeypatch.setenv("AEGIS_MAX_REPORT_BUNDLE_BYTES", "1")
    with pytest.raises(artifact_storage.ArtifactLimitError, match="Report bundle"):
        reporting.build_report_bundle_from_artifacts({"report.html": b"ok"})
