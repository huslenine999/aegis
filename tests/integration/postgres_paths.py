"""Exercise PostgreSQL-specific code paths against a real server.

Run by tests/integration/test_postgres_paths.py in a separate process, because
app.database chooses its backend at import time. Expects DATABASE_URL to name
an empty, disposable database.
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

from app import audit, database, evidence_signer, finding_queries, projects
from app.evidence import canonical_json, evidence_public_key, verify_manifest
from app.evidence_signer import SigningRefused, sign_requested_manifest

assert database.USING_POSTGRES, "DATABASE_URL must point at PostgreSQL"
checks = []


def check(name, condition):
    checks.append(name)
    if not condition:
        raise AssertionError(name)


database.initialize_database()
database.initialize_database()  # migrations are idempotent
with database.get_connection() as connection:
    version = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
check("all migrations applied", version == database.CURRENT_SCHEMA_VERSION)

with database.get_connection() as connection:
    tenant_id = int(connection.execute("SELECT id FROM tenants ORDER BY id LIMIT 1").fetchone()[0])
    user_id = int(connection.execute(
        """INSERT INTO auth_users (username, password_hash, role, active, created_at, tenant_id)
           VALUES ('pg-owner', 'unused', 'admin', 1, '2026-01-01T00:00:00+00:00', ?) RETURNING id""",
        (tenant_id,),
    ).fetchone()[0])

# --- Audit chain and checkpoints -------------------------------------------
for index in range(3):
    audit.record_audit(user_id, f"pg.event{index}", "project", index, tenant_id=tenant_id)
checkpoint = audit.create_audit_checkpoint(tenant_id)
check("audit chain verifies", audit.verify_audit_chain(tenant_id, [checkpoint])["valid"])
try:
    with database.get_connection() as connection:
        connection.execute("DELETE FROM audit_events WHERE tenant_id = ?", (tenant_id,))
    check("audit delete trigger", False)
except Exception as exc:  # noqa: BLE001 - asserting the trigger message
    check("audit delete trigger", "append-only" in str(exc))
with database.get_connection() as connection:
    # What a database superuser can do: bypass triggers and drop the newest event.
    connection.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
    connection.execute("DELETE FROM audit_events WHERE id = (SELECT MAX(id) FROM audit_events)")
    connection.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")
check("truncated chain still self-consistent", audit.verify_audit_chain(tenant_id)["valid"])
check("checkpoint detects truncation", not audit.verify_audit_chain(tenant_id, [checkpoint])["valid"])

# --- Findings search (LOWER/ESCAPE on PostgreSQL) ---------------------------
project_id = projects.create_project(
    name="Postgres", repository_url="", github_full_name="", default_branch="main",
    scan_preset="quick", user_id=user_id,
)
with database.get_connection() as connection:
    page = finding_queries.query_findings_page(connection, project_id, search="ÉVIL%_x", limit=5)
check("finding search runs", page["total"] == 0 and page["findings"] == [])

# --- Evidence signer ledger --------------------------------------------------
run_id = projects.create_scan_run(
    job_id="pg-job", project_id=project_id, requested_by=user_id, target="project", preset="quick",
)
projects.update_scan_run(run_id, state="reporting", progress=90)
scans = Path(tempfile.mkdtemp())
evidence_signer.SCANS_DIR = scans
run_dir = evidence_signer.run_directory(scans, "pg-job", tenant_id=tenant_id, project_id=project_id, create=True)
run_dir.mkdir(parents=True, exist_ok=True)
descriptor = {"schema_version": 1, "files": [], "file_count": 0, "total_bytes": 0}
(run_dir / "source-descriptor.json").write_text(json.dumps(descriptor))
(run_dir / "report.md").write_text("ok\n")
content_digest = hashlib.sha256(canonical_json({"schema_version": 1, "files": []})).hexdigest()
payload = {
    "schema_version": 3,
    "job_id": "pg-job",
    "project_id": project_id,
    "scan_run_id": run_id,
    "tenant_id": tenant_id,
    "policy_status": "BLOCKED",
    "operational_failures": [],
    "source": {"attestation": {
        "schema_version": 1, "status": "source-bound", "method": "stable-copy",
        "descriptor_sha256": hashlib.sha256(canonical_json(descriptor)).hexdigest(),
        "content_sha256": content_digest, "policy_sha256": "0" * 64,
        "file_count": 0, "total_bytes": 0,
    }},
    "artifacts": evidence_signer._artifact_inventory(run_dir),
}
signed = sign_requested_manifest(payload)
check("signer signs on PostgreSQL", verify_manifest(signed, evidence_public_key()["public_key"]))
try:
    sign_requested_manifest(payload)
    check("signing is one-shot", False)
except SigningRefused as exc:
    check("signing is one-shot", "already been signed" in str(exc))
try:
    with database.get_connection() as connection:
        connection.execute("UPDATE evidence_signatures SET manifest_sha256 = 'forged'")
    check("ledger update trigger", False)
except Exception as exc:  # noqa: BLE001
    check("ledger update trigger", "append-only" in str(exc))
projects.update_scan_run(run_id, state="completed", progress=100)
try:
    sign_requested_manifest(payload)
    check("completed runs refused", False)
except SigningRefused:
    check("completed runs refused", True)
check("finished runs stay final", projects.update_scan_run(run_id, state="reporting", progress=90) is False)
try:
    with database.get_connection() as connection:
        connection.execute("UPDATE scan_runs SET state = 'reporting' WHERE id = ?", (run_id,))
    check("finished-run trigger", False)
except Exception as exc:  # noqa: BLE001
    check("finished-run trigger", "immutable" in str(exc))
with database.get_connection() as connection:
    connection.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    remaining = connection.execute("SELECT COUNT(*) FROM evidence_signatures").fetchone()[0]
check("ledger rows cascade with their project", remaining == 0)

database.close_database_pool()
print(json.dumps({"passed": checks}))
sys.exit(0)
