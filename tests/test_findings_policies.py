from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
import hashlib
import json
import sys
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from threading import Event, local

import pytest
from cryptography.fernet import Fernet

from app import artifact_storage, database, findings, oidc, policies, projects, reporting
from app.routes import project_routes


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


def create_run(project_id: int, job_id: str, preset: str = "standard") -> int:
    return projects.create_scan_run(
        job_id=job_id,
        project_id=project_id,
        requested_by=10,
        target="project",
        preset=preset,
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
        ],
        "tools": [{"name": "Ruff", "status": "completed"}],
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
    assert findings.sync_findings(
        second,
        {"ruff": [], "tools": [{"name": "Ruff", "status": "completed"}]},
    )["resolved"] == 1
    assert findings.list_findings(project_id)[0]["status"] == "resolved"

    third = create_run(project_id, "third")
    assert findings.sync_findings(third, ruff_result())["reopened"] == 1
    reopened = findings.list_findings(project_id)[0]
    assert reopened["status"] == "open"
    assert reopened["occurrence_count"] == 2


def test_skipped_or_narrower_scans_do_not_resolve_findings(
    tmp_path, monkeypatch
):
    project_id = configure_database(tmp_path, monkeypatch)
    standard_run = create_run(project_id, "standard-finding", preset="standard")
    semgrep_result = {
        "semgrep": {
            "results": [{
                "check_id": "python-rce",
                "path": "src/app.py",
                "start": {"line": 4},
                "extra": {"severity": "ERROR", "message": "RCE"},
            }]
        },
        "tools": [{"name": "Semgrep", "status": "completed"}],
    }
    findings.sync_findings(standard_run, semgrep_result)

    quick_run = create_run(project_id, "quick-scan", preset="quick")
    result = findings.sync_findings(
        quick_run,
        {
            "semgrep": {"results": []},
            "tools": [{"name": "Semgrep", "status": "skipped"}],
        },
    )

    assert result["resolved"] == 0
    assert findings.list_findings(project_id)[0]["status"] == "open"

    # A Quick observation must not erase broader Standard-scan provenance.
    observed_quick = create_run(project_id, "quick-observed", preset="quick")
    findings.sync_findings(observed_quick, semgrep_result)
    final_quick = create_run(project_id, "quick-final", preset="quick")
    final_result = findings.sync_findings(
        final_quick,
        {"semgrep": {"results": []}, "tools": [{"name": "Semgrep", "status": "completed"}]},
    )
    assert final_result["resolved"] == 0
    assert findings.list_findings(project_id)[0]["status"] == "open"


def test_new_profile_preserves_retired_findings_and_requires_matching_coverage(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    old_run = create_run(project_id, "old-deep", preset="deep")
    findings.sync_findings(old_run, {
        "iac": {"findings": [{"rule_id": "CKV_1", "path": "Dockerfile"}]},
        "tools": [{"name": "IaC", "status": "completed"}],
    })
    codeql_report = {
        "status": "completed",
        "coverage": {"complete": True, "languages": ["python"]},
        "findings": [{"rule_id": "py/sql", "severity": "HIGH", "filename": "src/app.py", "line_number": 8, "issue_text": "SQL injection", "fingerprint": "stable-1"}],
    }
    coverage = {"CodeQL": {"complete": True, "source_scope": "repository", "languages": ["python"], "query_digest": "queries-v1"}}
    first = create_run(project_id, "new-deep", preset="deep")
    first_result = {
        "codeql": codeql_report, "profile_version": 2, "source_scope": "repository",
        "detector_coverage": coverage, "tools": [{"name": "CodeQL", "status": "completed"}],
    }
    findings.sync_findings(first, first_result)
    projects.update_scan_run(first, state="completed", progress=100, result=first_result)
    assert {row["tool"]: row["status"] for row in findings.list_findings(project_id)} == {"IaC": "open", "CodeQL": "open"}

    changed = create_run(project_id, "changed-queries", preset="deep")
    findings.sync_findings(changed, {
        "codeql": {**codeql_report, "findings": []}, "profile_version": 2,
        "source_scope": "repository", "detector_coverage": {"CodeQL": {**coverage["CodeQL"], "query_digest": "queries-v2"}},
        "tools": [{"name": "CodeQL", "status": "completed"}],
    })
    assert {row["tool"]: row["status"] for row in findings.list_findings(project_id)} == {"IaC": "open", "CodeQL": "open"}

    same = create_run(project_id, "same-queries", preset="deep")
    findings.sync_findings(same, {
        "codeql": {**codeql_report, "findings": []}, "profile_version": 2,
        "source_scope": "repository", "detector_coverage": coverage,
        "tools": [{"name": "CodeQL", "status": "completed"}],
    })
    assert {row["tool"]: row["status"] for row in findings.list_findings(project_id)} == {"IaC": "open", "CodeQL": "resolved"}


def test_out_of_order_scan_cannot_reopen_newer_finding(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    older = create_run(project_id, "older")
    newer = create_run(project_id, "newer")
    findings.sync_findings(newer, ruff_result())
    finding = findings.list_findings(project_id)[0]
    findings.sync_findings(older, ruff_result())
    assert findings.list_findings(project_id)[0]["last_seen_run_id"] == newer
    assert findings.list_findings(project_id)[0]["occurrence_count"] == finding["occurrence_count"]


def test_findings_pagination_counts_and_filters_cover_the_whole_project(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    run_id = create_run(project_id, "many-findings")
    result = ruff_result()
    result["ruff"] = [
        {**result["ruff"][0], "filename": f"src/{index}.py"}
        for index in range(200)
    ] + [{**result["ruff"][0], "code": "S310", "filename": "src/hidden.py"}]
    findings.sync_findings(run_id, result)
    with database.get_connection() as connection:
        connection.execute(
            "UPDATE security_findings SET status = 'resolved' WHERE severity = 'HIGH'"
        )
    principal = SimpleNamespace(user_id=10, role="operator", tenant_id=1)
    active = project_routes.project_findings(project_id, status="active", principal=principal)
    assert active["total"] == 1
    assert active["findings"][0]["path"] == "src/hidden.py"
    assert active["summary"] == {"open": 1, "blockers": 0}

    last_page = project_routes.project_findings(
        project_id, status="all", limit=200, offset=200, principal=principal,
    )
    assert last_page["total"] == 201
    assert last_page["limit"] == 200 and last_page["offset"] == 200
    assert [item["path"] for item in last_page["findings"]] == ["src/hidden.py"]
    assert last_page["summary"] == active["summary"]


def test_findings_search_escapes_wildcards_and_pages_have_stable_order(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    run_id = create_run(project_id, "literal-search")
    findings.sync_findings(run_id, {
        "ruff": [ruff_result(path)["ruff"][0] for path in ("src/100%_safe.py", "src/100XXsafe.py", "src/other.py")],
    })
    matched = findings.list_findings(project_id, search="100%_SAFE")
    assert [row["path"] for row in matched] == ["src/100%_safe.py"]
    ordered = findings.list_findings(project_id)
    assert [item["id"] for item in ordered] == sorted(item["id"] for item in ordered)
    assert findings.list_findings(project_id, limit=1, offset=1) == ordered[1:2]
    with database.get_connection() as connection:
        connection.execute(
            "UPDATE security_findings SET rule_id = NULL, path = NULL WHERE id = ?", (ordered[-1]["id"],),
        )
    assert len(findings.list_findings(project_id, search="eval")) == 3
    with database.get_connection() as connection:
        connection.execute("UPDATE auth_users SET username = 'member%_special' WHERE id = 11")
        connection.execute("UPDATE security_findings SET owner_id = 11 WHERE id = ?", (ordered[-1]["id"],))
    owner_page = findings.list_findings_page(project_id, search="MEMBER%_SPECIAL")
    assert owner_page["total"] == 1
    assert owner_page["findings"][0]["id"] == ordered[-1]["id"]


@pytest.mark.parametrize("field", ("path", "title", "rule_id", "tool", "owner"))
def test_findings_unicode_search_keeps_filtered_counts_and_pagination(tmp_path, monkeypatch, field):
    project_id = configure_database(tmp_path, monkeypatch)
    run_id = create_run(project_id, f"unicode-{field}")
    findings.sync_findings(run_id, {"ruff": [ruff_result(path)["ruff"][0] for path in ("one.py", "two.py", "other.py")]})
    records = findings.list_findings(project_id)
    with database.get_connection() as connection:
        if field == "owner":
            connection.execute("UPDATE auth_users SET username = 'Évil%_file.py' WHERE id = 11")
            connection.executemany(
                "UPDATE security_findings SET owner_id = 11, path = NULL, rule_id = NULL WHERE id = ?",
                [(row["id"],) for row in records[:2]],
            )
        else:
            connection.executemany(
                f"UPDATE security_findings SET {field} = ? WHERE id = ?",
                [(value, row["id"]) for value, row in zip(("Évil%_file.py", "ÉVIL%_FILE.py", "ÉvilXXfile.py"), records)],
            )
    first = findings.list_findings_page(project_id, search="éVIL%_file.py", limit=1)
    second = findings.list_findings_page(project_id, search="éVIL%_file.py", limit=1, offset=1)
    assert first["total"] == second["total"] == 2
    assert first["findings"][0]["id"] == records[0]["id"]
    assert second["findings"][0]["id"] == records[1]["id"]
    assert first["summary"] == second["summary"] == {"open": 3, "blockers": 3}


@pytest.mark.parametrize("options", [
    {"status": "unknown"}, {"severity": "unknown"}, {"limit": 0},
    {"limit": 501}, {"offset": -1}, {"search": "a" * 201},
])
def test_findings_reject_unbounded_or_invalid_filters(options):
    with pytest.raises(ValueError):
        findings.list_findings(1, **options)


def test_findings_summary_includes_accepted_risk_and_excludes_bac_blockers(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    run_id = create_run(project_id, "summary-statuses")
    findings.sync_findings(run_id, {"ruff": [ruff_result(str(index))["ruff"][0] for index in range(5)]})
    with database.get_connection() as connection:
        records = connection.execute("SELECT id FROM security_findings ORDER BY id").fetchall()
        connection.executemany("UPDATE security_findings SET status = ? WHERE id = ?", [
            (status, row[0]) for status, row in zip(
                ("accepted", "false_positive", "resolved", "acknowledged", "open"), records,
            )
        ])
        connection.execute("UPDATE security_findings SET tool = 'BAC' WHERE id = ?", (records[-1][0],))
    page = project_routes.project_findings(
        project_id, severity="LOW", principal=SimpleNamespace(user_id=10, role="operator", tenant_id=1),
    )
    assert page["findings"] == [] and page["total"] == 0
    assert page["summary"] == {"open": 3, "blockers": 2}


def test_codeql_findings_in_test_folders_are_marked_and_not_counted_as_blockers(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    run_id = create_run(project_id, "test-code")
    findings.sync_findings(run_id, {"ruff": [ruff_result(str(index))["ruff"][0] for index in range(3)]})
    with database.get_connection() as connection:
        records = connection.execute("SELECT id FROM security_findings ORDER BY id").fetchall()
        connection.executemany("UPDATE security_findings SET tool = 'CodeQL', path = ? WHERE id = ?", [
            ("tests/test_db.py", records[0][0]), ("app/db.py", records[1][0]), ("tests/db.py", records[2][0]),
        ])
        connection.execute("UPDATE security_findings SET tool = 'Ruff' WHERE id = ?", (records[2][0],))
    page = project_routes.project_findings(
        project_id, principal=SimpleNamespace(user_id=10, role="operator", tenant_id=1),
    )
    assert {item["path"]: item["test_code"] for item in page["findings"]} == {
        "tests/test_db.py": True, "app/db.py": False, "tests/db.py": False,
    }
    assert page["summary"] == {"open": 3, "blockers": 2}


@pytest.mark.parametrize("prior_run_count", (1, 2))
def test_findings_reconciliation_loads_reports_and_provenance_once(tmp_path, monkeypatch, prior_run_count):
    project_id = configure_database(tmp_path, monkeypatch)
    first = create_run(project_id, "coverage-first")
    coverage = {"Ruff": {"complete": True, "source_scope": "repository", "config_digest": "rules-v1"}}
    result = {
        **ruff_result(), "profile_version": 2, "source_scope": "repository", "detector_coverage": coverage,
        "ruff": [ruff_result(f"src/{index}.py")["ruff"][0] for index in range(40)],
        "large_evidence": "x" * 20000,
    }
    findings.sync_findings(first, result)
    projects.update_scan_run(first, state="completed", progress=100, result=result)
    if prior_run_count == 2:
        second = create_run(project_id, "coverage-second-observation")
        second_result = {**result, "ruff": result["ruff"][20:], "tools": []}
        findings.sync_findings(second, second_result)
        projects.update_scan_run(second, state="completed", progress=100, result=second_result)
    retired = create_run(project_id, "retired-tool", preset="deep")
    retired_result = {
        "iac": {"findings": [{"rule_id": "CKV_1", "path": "Dockerfile"}]},
        "large_evidence": "retired evidence" * 2000,
    }
    findings.sync_findings(retired, retired_result)
    projects.update_scan_run(retired, state="completed", progress=100, result=retired_result)
    current = create_run(project_id, "coverage-second")
    statements, decoded, reports = [], [], []
    real_connection, real_loads = database.get_connection, json.loads

    @contextmanager
    def traced_connection():
        with real_connection() as connection:
            class TracedConnection:
                def __getattr__(self, name):
                    return getattr(connection, name)

                def execute(self, sql, parameters=()):
                    statements.append(sql)
                    cursor = connection.execute(sql, parameters)
                    if "result_json" in sql:
                        class ReportCursor:
                            def fetchall(self):
                                rows = cursor.fetchall()
                                reports.extend(rows)
                                return rows

                        return ReportCursor()
                    return cursor

            yield TracedConnection()

    def tracked_loads(payload, *args, **kwargs):
        if "large_evidence" in payload:
            decoded.append(payload)
        return real_loads(payload, *args, **kwargs)

    monkeypatch.setattr(findings, "get_connection", traced_connection)
    monkeypatch.setattr(findings.json, "loads", tracked_loads)
    reconciliation = findings.sync_findings(current, {
        "ruff": [], "profile_version": 2, "source_scope": "repository",
        "detector_coverage": coverage, "tools": [{"name": "Ruff", "status": "completed"}],
    })
    assert reconciliation["resolved"] == 40
    assert len(decoded) == prior_run_count
    selects = [sql for sql in statements if sql.lstrip().upper().startswith("SELECT")]
    assert len(selects) <= 5
    report_reads = [sql for sql in selects if "result_json" in sql]
    assert len(report_reads) == 1
    assert len(reports) == prior_run_count


def test_older_empty_scan_cannot_resolve_findings_observed_by_a_newer_run(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    older, newer = create_run(project_id, "old-empty"), create_run(project_id, "new-observed")
    findings.sync_findings(newer, ruff_result())
    result = findings.sync_findings(older, {"ruff": [], "tools": [{"name": "Ruff", "status": "completed"}]})
    assert result["resolved"] == 0
    assert findings.list_findings(project_id)[0]["status"] == "open"


@pytest.mark.parametrize("change", [
    {"profile_version": 3}, {"source_scope": "partial"}, {"operational_failures": ["Ruff unavailable"]},
    {"detector_coverage": {}}, {"detector_coverage": {"Ruff": {"complete": False}}},
])
def test_reconciliation_requires_complete_matching_scope_and_coverage(tmp_path, monkeypatch, change):
    project_id = configure_database(tmp_path, monkeypatch)
    first = create_run(project_id, "complete-observation")
    result = {
        **ruff_result(), "profile_version": 2, "source_scope": "repository",
        "detector_coverage": {"Ruff": {"complete": True, "source_scope": "repository", "config_digest": "v1"}},
    }
    findings.sync_findings(first, result)
    projects.update_scan_run(first, state="completed", progress=100, result=result)
    current = create_run(project_id, "incomplete-comparison")
    assert findings.sync_findings(current, {**result, "ruff": [], **change})["resolved"] == 0
    assert findings.list_findings(project_id)[0]["status"] == "open"


def test_concurrent_reconciliation_serializes_before_loading_finding_snapshots(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    older, newer = create_run(project_id, "concurrent-old"), create_run(project_id, "concurrent-new")
    older_snapshot, newer_snapshot, release_older, newer_started = (Event() for _ in range(4))
    thread_state, real_connection = local(), database.get_connection

    @contextmanager
    def paused_connection():
        with real_connection() as connection:
            class PausedConnection:
                def __getattr__(self, name):
                    return getattr(connection, name)

                def execute(self, sql, parameters=()):
                    if "FROM security_findings" in sql and not thread_state.paused:
                        thread_state.paused = True
                        if thread_state.run_id == older:
                            older_snapshot.set()
                            assert release_older.wait(3)
                        else:
                            newer_snapshot.set()
                    return connection.execute(sql, parameters)

            yield PausedConnection()

    def reconcile(run_id):
        thread_state.run_id, thread_state.paused = run_id, False
        if run_id == newer:
            newer_started.set()
        return findings.sync_findings(run_id, ruff_result())

    monkeypatch.setattr(findings, "get_connection", paused_connection)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(reconcile, older)
        assert older_snapshot.wait(2)
        second = executor.submit(reconcile, newer)
        try:
            assert newer_started.wait(2)
            assert not newer_snapshot.wait(0.2)
        finally:
            release_older.set()
        assert first.result(timeout=5)["created"] == 1
        assert second.result(timeout=5)["created"] == 0
    monkeypatch.setattr(findings, "get_connection", real_connection)
    finding = findings.list_findings(project_id)[0]
    assert finding["last_seen_run_id"] == newer and finding["occurrence_count"] == 2


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


def test_new_policy_rejects_retired_required_tools():
    with pytest.raises(ValueError, match="unknown required tool"):
        policies.normalize_definition({"required_tools": ["ClamAV"]})
    assert policies.normalize_definition({"required_tools": ["CodeQL"]})["required_tools"] == ["CodeQL"]


def test_policy_simulation_cannot_pass_incomplete_codeql(tmp_path, monkeypatch):
    project_id = configure_database(tmp_path, monkeypatch)
    run_id = create_run(project_id, "incomplete-codeql", preset="deep")
    projects.update_scan_run(run_id, state="completed", progress=100, result={
        "profile_version": 2,
        "codeql": {"status": "completed", "findings": [], "coverage": {"complete": False, "languages": ["python"]}},
        "tools": [{"name": "CodeQL", "status": "completed"}],
    })
    decision = policies.simulate_policy(project_id, run_id, {"required_tools": ["CodeQL"]})
    assert decision["status"] == "ERROR"


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
