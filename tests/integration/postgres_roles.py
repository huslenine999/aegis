"""Run each service's real code under its least-privilege PostgreSQL login.

Phases (argv[1]): owner, worker, signer, broker, notifier. Driven by
tests/integration/test_postgres_paths.py; each phase is a separate process
whose DATABASE_URL names that service's login. AEGIS_DATA_DIR is shared.
"""

import json
import os
import sys
from pathlib import Path

from app import database

WORKDIR = Path(os.environ["AEGIS_DATA_DIR"])
STATE = WORKDIR / "roles-state.json"
results: dict[str, object] = {"phase": sys.argv[1], "passed": []}


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    results["passed"].append(name)


def denied(name, statement, parameters=()):
    try:
        with database.get_connection() as connection:
            connection.execute(statement, parameters)
    except Exception as exc:  # noqa: BLE001 - asserting PostgreSQL's refusal
        message = str(exc).lower()
        check(name, "permission denied" in message or "must be owner" in message or "immutable" in message)
        return
    check(name, False)


def owner():
    from app import github_integration, github_lifecycle, notifications, projects
    from app.evidence import canonical_json
    import hashlib

    database.initialize_database()
    with database.get_connection() as connection:
        roles = {row[0] for row in connection.execute(
            "SELECT rolname FROM pg_roles WHERE rolname = ANY(?)", (list(database.SERVICE_DATABASE_ROLES),)
        ).fetchall()}
        tenant_id = int(connection.execute("SELECT id FROM tenants ORDER BY id LIMIT 1").fetchone()[0])
        user_id = int(connection.execute(
            """INSERT INTO auth_users (username, password_hash, role, active, created_at, tenant_id)
               VALUES ('owner', 'secret-hash', 'admin', 1, '2026-01-01T00:00:00+00:00', ?) RETURNING id""",
            (tenant_id,),
        ).fetchone()[0])
        connection.execute(
            """INSERT INTO github_connections (user_id, github_login, token_encrypted, scopes, connected_at)
               VALUES (?, 'owner', ?, 'repo', '2026-01-01T00:00:00+00:00')""",
            (user_id, github_integration._encrypt("gho_user_token")),
        )
    check("service logins created", roles >= {"aegis_worker", "aegis_signer", "aegis_github_broker", "aegis_notifier"})
    project_id = projects.create_project(
        name="Roles", repository_url="", github_full_name="example/api", default_branch="main",
        scan_preset="quick", user_id=user_id, tenant_id=tenant_id,
    )
    github_lifecycle.resolve_github_webhook_binding(
        repository_full_name="example/api", repository_id=101, installation_id=55,
    )
    worker_run = projects.create_scan_run(
        job_id="role-worker", project_id=project_id, requested_by=user_id, target="project", preset="quick",
    )
    broker_run = projects.create_scan_run(
        job_id="role-broker", project_id=project_id, requested_by=user_id, target="project", preset="quick",
        github_installation_id=55,
    )
    signer_run = projects.create_scan_run(
        job_id="role-signer", project_id=project_id, requested_by=user_id, target="project", preset="quick",
    )
    projects.update_scan_run(signer_run, state="reporting", progress=90)
    notifications.create_channel(
        project_id=project_id, name="ops", channel_type="email", config={"to": "ops@example.com"},
        events=["completed"], created_by=user_id,
    )
    from app.artifact_storage import run_directory
    from app.evidence_signer import _artifact_inventory

    run_dir = run_directory(database.SCANS_DIR, "role-signer", tenant_id=tenant_id, project_id=project_id, create=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    descriptor = {"schema_version": 1, "files": [], "file_count": 0, "total_bytes": 0}
    (run_dir / "source-descriptor.json").write_text(json.dumps(descriptor))
    (run_dir / "report.md").write_text("ok\n")
    payload = {
        "schema_version": 3, "job_id": "role-signer", "project_id": project_id, "scan_run_id": signer_run,
        "tenant_id": tenant_id, "policy_status": "BLOCKED", "operational_failures": [],
        "source": {"attestation": {
            "schema_version": 1, "status": "source-bound", "method": "stable-copy",
            "descriptor_sha256": hashlib.sha256(canonical_json(descriptor)).hexdigest(),
            "content_sha256": hashlib.sha256(canonical_json({"schema_version": 1, "files": []})).hexdigest(),
            "policy_sha256": "0" * 64, "file_count": 0, "total_bytes": 0,
        }},
        "artifacts": _artifact_inventory(run_dir),
    }
    source = WORKDIR / "source"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("def run(value):\n    return eval(value)\n")
    STATE.write_text(json.dumps({
        "project_id": project_id, "user_id": user_id, "tenant_id": tenant_id,
        "worker_run": worker_run, "broker_run": broker_run, "signer_run": signer_run,
        "signer_payload": payload, "source": str(source),
    }))


def common_denials(service):
    denied(f"{service}: no password hashes", "SELECT password_hash FROM auth_users")
    denied(f"{service}: no audit rewrite", "UPDATE audit_events SET action = 'forged'")
    denied(f"{service}: no ledger deletes", "DELETE FROM evidence_signatures")
    denied(f"{service}: cannot drop triggers", "DROP TRIGGER scan_runs_final_immutable ON scan_runs")
    denied(f"{service}: cannot disable triggers", "ALTER TABLE scan_runs DISABLE TRIGGER USER")


def worker_phase(state):
    from app import projects, worker
    from app.scan_engine import ScanJobPayload

    database.require_least_privilege_role(timeout=10)
    check("worker: runs as a least-privilege login", True)
    worker.async_scan_task(ScanJobPayload(
        "role-worker", "project", custom_file_path=state["source"], scan_run_id=state["worker_run"],
        project_id=state["project_id"], requested_by=state["user_id"], preset="quick",
    ))
    run = projects.get_scan_run(state["worker_run"])
    check("worker: completed a real scan", run["state"] == "completed")
    with database.get_connection() as connection:
        findings = connection.execute(
            "SELECT COUNT(*) FROM security_findings WHERE project_id = ?", (state["project_id"],)
        ).fetchone()[0]
    check("worker: recorded findings", findings >= 1)
    common_denials("worker")
    denied("worker: no stored GitHub tokens", "SELECT token_encrypted FROM github_connections")
    denied("worker: no notification secrets", "SELECT config_encrypted FROM notification_channels")
    denied("worker: cannot move runs between projects", "UPDATE scan_runs SET project_id = project_id")
    denied("worker: cannot sign", "INSERT INTO evidence_signatures (scan_run_id, job_id, manifest_sha256, key_id, signed_at) VALUES (1, 'x', 'x', 'x', 'x')")
    denied("worker: cannot reopen finished runs", "UPDATE scan_runs SET state = 'reporting' WHERE id = ?", (state["worker_run"],))


def signer_phase(state):
    from app.evidence import evidence_public_key, verify_manifest
    from app.evidence_signer import sign_requested_manifest

    database.require_least_privilege_role(timeout=10)
    signed = sign_requested_manifest(state["signer_payload"])
    check("signer: signs as a least-privilege login", verify_manifest(signed, evidence_public_key()["public_key"]))
    common_denials("signer")
    denied("signer: no scan results", "SELECT result_json FROM scan_runs")
    denied("signer: no state changes", "UPDATE scan_runs SET progress = 1")


def broker_phase(state):
    from app import github_integration
    from app.github_broker import issue_clone_token

    database.require_least_privilege_role(timeout=10)
    oauth = issue_clone_token({"scan_run_id": state["signer_run"]})
    check("broker: decrypts the requester's OAuth token", oauth == {"token": "gho_user_token", "kind": "oauth"})

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"token": "ghs_scoped"}

    sent = {}
    github_integration.github_app_jwt = lambda: "jwt"
    github_integration.requests.post = lambda url, **kwargs: sent.update(kwargs) or Response()
    token = issue_clone_token({"scan_run_id": state["broker_run"]})
    check("broker: scoped installation token", token == {"token": "ghs_scoped", "kind": "installation"})
    check("broker: token scope sent", sent["json"] == {"repositories": ["api"], "permissions": {"contents": "read"}})
    common_denials("broker")
    denied("broker: no scan results", "SELECT result_json FROM scan_runs")
    denied("broker: no findings", "SELECT * FROM security_findings")


def notifier_phase(state):
    from app import notifications

    database.require_least_privilege_role(timeout=10)
    delivered = []
    notifications._deliver = lambda channel_type, config, event, payload: delivered.append((channel_type, config))
    notifications.send_project_notification(state["project_id"], "completed", {"project_name": "Roles"})
    check("notifier: delivered with decrypted config", delivered == [("email", {"to": "ops@example.com"})])
    common_denials("notifier")
    denied("notifier: no scan runs", "SELECT * FROM scan_runs")
    denied("notifier: no findings", "SELECT * FROM security_findings")


phase = sys.argv[1]
if phase == "owner":
    owner()
else:
    state = json.loads(STATE.read_text())
    {"worker": worker_phase, "signer": signer_phase, "broker": broker_phase, "notifier": notifier_phase}[phase](state)
database.close_database_pool()
print(json.dumps(results))
