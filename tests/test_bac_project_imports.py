"""Research imports use an isolated database, local artifacts, and no lab process."""

import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import importlib
import io
import json
from threading import Barrier
from types import SimpleNamespace
from zipfile import ZipFile

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

from app import artifact_storage, auth, database, findings, policies, projects, web_common
from app.bac_reports import export_report
from app.evidence import canonical_json, evidence_public_key
from app.routes import artifact_routes, project_routes


@pytest.fixture(scope="session", autouse=True)
def application_lifespan():
    yield


@pytest.fixture(scope="session", autouse=True)
def preserve_checked_in_reports():
    yield


@pytest.fixture(autouse=True)
def mock_rq_and_redis(monkeypatch):
    monkeypatch.setenv("AEGIS_SKIP_EXTERNAL_SCANNERS", "true")
    monkeypatch.setenv("AEGIS_ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("AEGIS_EVIDENCE_SIGNING_KEY", base64.urlsafe_b64encode(bytes(range(32))).decode())
    yield


def _principal(user_id=10, tenant_id=1, role="operator", **extra):
    return SimpleNamespace(
        **{"user_id": user_id, "tenant_id": tenant_id, "role": role,
           "username": f"user-{user_id}", "auth_method": "session",
           "scopes": ("*",), "csrf_token": "", **extra}
    )


def _project(user_id=10):
    project_id = projects.create_project(
        name="Research", repository_url="", github_full_name="", default_branch="main",
        scan_preset="standard", user_id=user_id,
    )
    return projects.get_project(project_id)


@pytest.fixture
def environment(tmp_path, monkeypatch):
    bac = importlib.import_module("app.bac_projects")
    scans_root = tmp_path / "scans"
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "imports.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    for module in (projects, findings, policies, bac):
        monkeypatch.setattr(module, "get_connection", database.get_connection, raising=False)
        monkeypatch.setattr(module, "USING_POSTGRES", False, raising=False)
    for module in (database, bac, artifact_routes, project_routes):
        monkeypatch.setattr(module, "SCANS_DIR", scans_root, raising=False)
    database.initialize_database()
    with database.get_connection() as connection:
        connection.execute(
            "INSERT INTO tenants (id, slug, name, created_at) VALUES (2, 'other', 'Other', ?)",
            ("2026-10-08T00:00:00+00:00",),
        )
        connection.executemany(
            """INSERT INTO auth_users
               (id, tenant_id, username, password_hash, role, active, created_at)
               VALUES (?, ?, ?, 'unused', ?, 1, ?)""",
            [(10, 1, "owner", "operator", "2026-10-08T00:00:00+00:00"),
             (11, 1, "viewer", "viewer", "2026-10-08T00:00:00+00:00"),
             (12, 1, "stranger", "operator", "2026-10-08T00:00:00+00:00"),
             (13, 1, "project-viewer", "operator", "2026-10-08T00:00:00+00:00"),
             (20, 2, "other-owner", "operator", "2026-10-08T00:00:00+00:00")],
        )
    project = _project()
    projects.set_project_member(project["id"], "viewer", "viewer")
    projects.set_project_member(project["id"], "project-viewer", "viewer")
    key = evidence_public_key()["public_key"]
    monkeypatch.setenv("AEGIS_BAC_IMPORT_PUBLIC_KEY", key)

    def admitted(artifacts, pinned_key):
        assert pinned_key == key
        manifest = json.loads(artifacts["scan-manifest.json"])
        return {"manifest": manifest,
                "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
                "report": json.loads(artifacts["report.json"]),
                "matrix": json.loads(artifacts["matrix.json"])}

    monkeypatch.setattr(bac, "validate_bac_bundle", admitted)
    return SimpleNamespace(bac=bac, project=project, scans_root=scans_root, key=key)


@pytest.fixture
def bundle_factory(tmp_path):
    def make(*, outcome="violation", mode="vulnerable", corpus="synthetic-import-v1", nonce="1"):
        case = {"id": "cross-owner", "split": "development", "actor": "alice",
                "operation": "read", "resource": "bob-private-1", "expected_allowed": False}
        matrix = {"schema_version": 1, "corpus_id": corpus,
                  "description": "Synthetic import test corpus.", "cases": [case]}
        result = {**case, "status": outcome, "reason": "Synthetic observed outcome.",
                  "http_status": 200 if outcome == "violation" else 403,
                  "duration_seconds": 0.1, "evidence": {}}
        observed = [{"fingerprint": hashlib.sha256(canonical_json(
                         {field: case[field] for field in ("actor", "operation", "resource")}
                     )).hexdigest(), "tool": "BAC", "rule_id": "read", "severity": "HIGH",
                     "title": "Confirmed broken access control in synthetic lab", "case_id": case["id"],
                     "actor": case["actor"], "resource": case["resource"], "reason": result["reason"],
                     "evidence_artifact": "evidence.json"}] if outcome == "violation" else []
        status, code = ("blocked", 1) if observed else ("error", 2) if outcome == "inconclusive" else ("allowed", 0)
        report = {
            "schema_version": 1, "kind": "bac-research", "run_id": f"synthetic-run-{nonce}",
            "mode": mode, "split": "development", "corpus_id": corpus,
            "matrix_sha256": hashlib.sha256(canonical_json(matrix)).hexdigest(),
            "started_at": "2026-10-08T00:00:00+00:00", "completed_at": "2026-10-08T00:01:00+00:00",
            "status": status, "exit_code": code, "results": [result], "findings": observed,
            "metrics": {"cases": 1, "violations": len(observed), "inconclusive": int(outcome == "inconclusive")},
            "limitations": ["Owned synthetic lab only; no source attestation."],
        }
        destination = tmp_path / f"export-{nonce}-{mode}-{outcome}-{corpus}"
        export_report(report, matrix, destination)
        return {path.name: path.read_bytes() for path in destination.iterdir()}

    return make


def _import(environment, artifacts, *, project=None, requested_by=10):
    return environment.bac.import_bac_report(
        project=project or environment.project, requested_by=requested_by, artifacts=artifacts,
    )


def _counts():
    with database.get_connection() as connection:
        return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("scan_runs", "scan_artifacts", "security_findings", "finding_occurrences", "finding_events")}


def _orphan_directory(environment, artifacts):
    manifest_digest = hashlib.sha256(canonical_json(json.loads(artifacts["scan-manifest.json"]))).hexdigest()
    identity = {"tenant_id": environment.project["tenant_id"], "project_id": environment.project["id"],
                "manifest_sha256": manifest_digest}
    job_id = "bac-" + hashlib.sha256(canonical_json(identity)).hexdigest()
    return (environment.scans_root / "tenants" / str(identity["tenant_id"]) / "projects"
            / str(identity["project_id"]) / "runs" / job_id)


def _seed_orphan(environment, artifacts):
    directory = _orphan_directory(environment, artifacts)
    directory.mkdir(parents=True, mode=0o700)
    for name, content in artifacts.items():
        path = directory / name
        path.write_bytes(content)
        path.chmod(0o600)
    return directory


def _file_facts(directory):
    return {path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
            for path in directory.iterdir() if path.is_file()}


def _source_run(project_id, job_id, result):
    run_id = projects.create_scan_run(
        job_id=job_id, project_id=project_id, requested_by=10, target="project", preset="standard",
    )
    synced = findings.sync_findings(run_id, result)
    projects.update_scan_run(run_id, state="completed", progress=100, result={**result, "finding_sync": synced})
    return run_id


def _source_result():
    return {"ruff": [{"code": "S307", "filename": "src/app.py", "message": "Use of eval",
                      "location": {"row": 12}}], "tools": [{"name": "Ruff", "status": "completed"}]}


def _client(environment, monkeypatch, *, principal=None, recent=True):
    monkeypatch.setattr(auth, "AUTH_REQUIRED", True)
    monkeypatch.setattr(web_common, "AUTH_REQUIRED", True)
    monkeypatch.setattr(auth, "principal_from_request", lambda request: principal or _principal())
    monkeypatch.setattr(web_common, "session_authentication_is_recent", lambda session: recent)
    app = FastAPI()
    app.include_router(project_routes.router)
    app.include_router(artifact_routes.router)
    return TestClient(app)


def _multipart(artifacts):
    return [("files", (name, content, "application/octet-stream")) for name, content in artifacts.items()]


def test_import_persists_completed_research_run_and_exact_private_artifacts(environment, bundle_factory):
    artifacts = bundle_factory()
    original = copy.deepcopy(artifacts)
    imported = _import(environment, artifacts)
    assert imported == {"scan_run_id": imported["scan_run_id"], "imported": True, "research_only": True}
    run = projects.get_scan_run(imported["scan_run_id"])
    assert (run["project_id"], run["tenant_id"], run["requested_by"]) == (environment.project["id"], 1, 10)
    assert (run["target"], run["preset"], run["state"], run["progress"]) == ("bac-research", "quick", "completed", 100)
    assert run["policy_version_id"] is None
    assert run["source_revision"] is None
    result = run["result"]
    assert result["research_only"] is True
    assert result["gate_eligible"] is False
    assert result["source_attestation"] == "not-claimed"
    assert result["manifest_sha256"] == hashlib.sha256(canonical_json(json.loads(artifacts["scan-manifest.json"]))).hexdigest()
    assert result["bac_report"] == json.loads(artifacts["report.json"])
    assert len(result["bac_findings"]) == 1
    assert result["finding_sync"] == {"observed": 1, "created": 1, "reopened": 0, "resolved": 0}
    assert artifacts == original
    assert "policy" not in result
    records = projects.list_scan_artifacts(run["id"])
    assert {item["name"] for item in records} == set(artifacts)
    directory = environment.scans_root / "tenants" / "1" / "projects" / str(run["project_id"]) / "runs" / run["job_id"]
    assert directory.stat().st_mode & 0o077 == 0
    assert not (environment.scans_root / "runs" / run["job_id"]).exists()
    for item in records:
        path = directory / item["name"]
        assert path.read_bytes() == artifacts[item["name"]]
        assert path.stat().st_mode & 0o077 == 0
        assert item["size"] == len(artifacts[item["name"]])
        assert item["sha256"] == hashlib.sha256(artifacts[item["name"]]).hexdigest()
        assert item["backend"] == "local"


def test_duplicate_and_equivalent_manifest_import_is_idempotent(environment, bundle_factory):
    artifacts = bundle_factory()
    first = _import(environment, artifacts)
    equivalent = {**artifacts, "scan-manifest.json": json.dumps(json.loads(artifacts["scan-manifest.json"]), indent=4).encode()}
    second = _import(environment, equivalent)
    assert second == {**first, "imported": False}
    assert _counts() == {"scan_runs": 1, "scan_artifacts": 8, "security_findings": 1, "finding_occurrences": 1, "finding_events": 1}
    run = projects.get_scan_run(first["scan_run_id"])
    directory = artifact_storage.run_directory(environment.scans_root, run["job_id"], tenant_id=1, project_id=run["project_id"])
    assert (directory / "scan-manifest.json").read_bytes() == artifacts["scan-manifest.json"]


def test_concurrent_duplicate_import_creates_one_run_and_occurrence(environment, bundle_factory):
    artifacts = bundle_factory()
    barrier = Barrier(2)

    def import_after_barrier():
        barrier.wait(timeout=10)
        return _import(environment, artifacts)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(import_after_barrier) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    assert results[0]["scan_run_id"] == results[1]["scan_run_id"]
    assert sorted(result["imported"] for result in results) == [False, True]
    assert _counts() == {"scan_runs": 1, "scan_artifacts": 8, "security_findings": 1, "finding_occurrences": 1, "finding_events": 1}


@pytest.mark.parametrize("failure", ["publication", "finding-sync"])
def test_import_rolls_back_database_and_files_after_partial_failure(environment, bundle_factory, monkeypatch, failure):
    artifacts = bundle_factory()
    seam = "publish_artifacts" if failure == "publication" else "sync_findings"
    original = getattr(environment.bac, seam)

    def fail_after_side_effect(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("injected import failure")

    with monkeypatch.context() as patch:
        patch.setattr(environment.bac, seam, fail_after_side_effect)
        with pytest.raises(RuntimeError, match="injected import failure"):
            _import(environment, artifacts)
    assert all(count == 0 for count in _counts().values())
    assert not [path for path in environment.scans_root.rglob("*") if path.is_file()]
    assert _import(environment, artifacts)["imported"] is True


def test_admission_failure_happens_before_database_or_artifact_changes(environment, bundle_factory, monkeypatch):
    def reject(*args):
        assert all(count == 0 for count in _counts().values())
        assert not environment.scans_root.exists()
        raise ValueError("invalid signed research bundle")

    monkeypatch.setattr(environment.bac, "validate_bac_bundle", reject)
    with pytest.raises(ValueError, match="invalid signed"):
        _import(environment, bundle_factory())
    assert all(count == 0 for count in _counts().values())
    assert not environment.scans_root.exists()


def test_commit_failure_rolls_back_database_and_same_bundle_retry_recovers(environment, bundle_factory, monkeypatch):
    artifacts = bundle_factory()
    original = environment.bac.get_connection

    class FailedCommit:
        def __enter__(self):
            self.connection = original()
            return self.connection.__enter__()

        def __exit__(self, exc_type, exc, traceback):
            if exc_type is None:
                failure = RuntimeError("injected database commit failure")
                self.connection.__exit__(RuntimeError, failure, None)
                raise failure
            return self.connection.__exit__(exc_type, exc, traceback)

    with monkeypatch.context() as patch:
        patch.setattr(environment.bac, "get_connection", FailedCommit)
        with pytest.raises(RuntimeError, match="injected database commit failure"):
            _import(environment, artifacts)
    assert all(count == 0 for count in _counts().values())
    imported = _import(environment, artifacts)
    assert imported["imported"] is True
    assert _counts() == {"scan_runs": 1, "scan_artifacts": 8, "security_findings": 1, "finding_occurrences": 1, "finding_events": 1}
    assert {name: facts[0] for name, facts in _file_facts(_orphan_directory(environment, artifacts)).items()} == artifacts


def test_exact_orphan_reuse_preserves_original_bytes_and_files(environment, bundle_factory):
    artifacts = bundle_factory()
    directory = _seed_orphan(environment, artifacts)
    before = _file_facts(directory)
    imported = _import(environment, artifacts)
    assert imported["imported"] is True
    assert _file_facts(directory) == before
    assert _counts() == {"scan_runs": 1, "scan_artifacts": 8, "security_findings": 1, "finding_occurrences": 1, "finding_events": 1}


@pytest.mark.parametrize("change", ["mismatch", "missing", "extra", "file-symlink", "directory-symlink"])
def test_unusable_orphan_is_rejected_without_altering_existing_evidence(environment, bundle_factory, tmp_path, change):
    artifacts = bundle_factory()
    directory = _orphan_directory(environment, artifacts)
    outside = tmp_path / "original-evidence"
    if change == "directory-symlink":
        outside.mkdir(mode=0o700)
        for name, content in artifacts.items():
            (outside / name).write_bytes(content)
        directory.parent.mkdir(parents=True)
        directory.symlink_to(outside, target_is_directory=True)
    else:
        directory = _seed_orphan(environment, artifacts)
        if change == "mismatch":
            (directory / "report.json").write_bytes(b"original unrelated evidence")
        elif change == "missing":
            (directory / "report.json").unlink()
        elif change == "extra":
            (directory / "valuable-note.txt").write_bytes(b"original note")
        else:
            outside.write_bytes(artifacts["report.json"])
            (directory / "report.json").unlink()
            (directory / "report.json").symlink_to(outside)
    before = _file_facts(directory)
    before_names = {path.name for path in directory.iterdir()}
    with pytest.raises((RuntimeError, ValueError)):
        _import(environment, artifacts)
    assert all(count == 0 for count in _counts().values())
    assert _file_facts(directory) == before
    assert {path.name for path in directory.iterdir()} == before_names
    if change == "directory-symlink":
        assert directory.is_symlink()
        assert {path.name: path.read_bytes() for path in outside.iterdir()} == artifacts
    elif change == "file-symlink":
        assert (directory / "report.json").is_symlink()
        assert outside.read_bytes() == artifacts["report.json"]


def test_rollback_after_orphan_adoption_preserves_orphan_for_retry(environment, bundle_factory, monkeypatch):
    artifacts = bundle_factory()
    directory = _seed_orphan(environment, artifacts)
    before = _file_facts(directory)
    original = environment.bac.sync_findings

    def fail_after_sync(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("injected adopted-orphan sync failure")

    with monkeypatch.context() as patch:
        patch.setattr(environment.bac, "sync_findings", fail_after_sync)
        with pytest.raises(RuntimeError, match="injected adopted-orphan sync failure"):
            _import(environment, artifacts)
    assert all(count == 0 for count in _counts().values())
    assert _file_facts(directory) == before
    assert _import(environment, artifacts)["imported"] is True
    assert _file_facts(directory) == before


def test_missing_server_pin_fails_closed_without_changes(environment, bundle_factory, monkeypatch):
    monkeypatch.delenv("AEGIS_BAC_IMPORT_PUBLIC_KEY", raising=False)
    monkeypatch.setattr(environment.bac, "validate_bac_bundle", lambda *args: pytest.fail("admission without server pin"))
    with pytest.raises(RuntimeError, match="AEGIS_BAC_IMPORT_PUBLIC_KEY|configured|configuration"):
        _import(environment, bundle_factory())
    assert all(count == 0 for count in _counts().values())
    assert not environment.scans_root.exists()


@pytest.mark.parametrize("encoding", ["canonical", "noncanonical"])
def test_production_rejects_published_development_pin_before_admission(environment, bundle_factory, monkeypatch, encoding):
    artifacts = bundle_factory()
    monkeypatch.setenv("AEGIS_ENV", "development")
    monkeypatch.delenv("AEGIS_EVIDENCE_SIGNING_KEY")
    development_key = evidence_public_key()["public_key"]
    if encoding == "noncanonical":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        equivalent = development_key[:-1] + alphabet[alphabet.index(development_key[-1]) ^ 1]
        assert base64.urlsafe_b64decode(equivalent + "=") == base64.urlsafe_b64decode(development_key + "=")
        development_key = equivalent
    monkeypatch.setenv("AEGIS_BAC_IMPORT_PUBLIC_KEY", development_key)
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setattr(environment.bac, "validate_bac_bundle", lambda *args: pytest.fail("production trusted the published development pin"))
    with pytest.raises(RuntimeError, match="development|production|key"):
        _import(environment, artifacts)
    assert all(count == 0 for count in _counts().values())
    assert not environment.scans_root.exists()


@pytest.mark.parametrize("outcome,mode,status,code", [
    ("violation", "vulnerable", "blocked", 1),
    ("no_violation", "fixed", "allowed", 0),
    ("inconclusive", "vulnerable", "error", 2),
])
def test_research_history_separates_verdict_from_gate_decision(environment, bundle_factory, outcome, mode, status, code):
    imported = _import(environment, bundle_factory(outcome=outcome, mode=mode))
    history = projects.list_scan_runs(environment.project["id"])[0]
    assert history["id"] == imported["scan_run_id"]
    assert history["state"] == ("failed" if code == 2 else "completed")
    assert history["run_kind"] == "bac_research"
    assert history["research_exit_code"] == code
    assert history["research_status"] == status
    assert history["research_mode"] == mode
    assert history["decision"] is None
    assert history["has_report"] is True


def test_fixed_and_incomplete_imports_never_close_existing_research_findings(environment, bundle_factory):
    first = _import(environment, bundle_factory())
    finding = findings.list_findings(environment.project["id"])[0]
    for outcome, mode, nonce in [("no_violation", "fixed", "2"), ("inconclusive", "vulnerable", "3")]:
        imported = _import(environment, bundle_factory(outcome=outcome, mode=mode, nonce=nonce))
        assert projects.get_scan_run(imported["scan_run_id"])["result"]["finding_sync"]["resolved"] == 0
    current = findings.list_findings(environment.project["id"])[0]
    assert current["status"] == "open"
    assert current["last_seen_run_id"] == first["scan_run_id"]
    assert current["occurrence_count"] == finding["occurrence_count"] == 1


@pytest.mark.parametrize("status", ["acknowledged", "accepted", "false_positive", "resolved"])
def test_fresh_research_observation_preserves_manual_triage(environment, bundle_factory, status):
    _import(environment, bundle_factory())
    finding_id = findings.list_findings(environment.project["id"])[0]["id"]
    change = {"status": status, "resolution_note": "Reviewed synthetic research finding."}
    if status == "accepted":
        change = {**change, "accepted_until": "2099-01-01T00:00:00+00:00"}
    findings.update_finding(environment.project["id"], finding_id, 10, change)
    before = findings.get_finding(environment.project["id"], finding_id)
    imported = _import(environment, bundle_factory(nonce="2"))
    after = findings.get_finding(environment.project["id"], finding_id)
    assert after["status"] == status
    assert after["resolution_note"] == before["resolution_note"]
    assert after["accepted_until"] == before["accepted_until"]
    assert after["occurrence_count"] == 2
    assert after["last_seen_run_id"] == imported["scan_run_id"]
    assert projects.get_scan_run(imported["scan_run_id"])["result"]["finding_sync"]["reopened"] == 0


def test_research_findings_include_corpus_identity_and_do_not_affect_source_findings(environment, bundle_factory):
    source = _source_run(environment.project["id"], "source-before-import", _source_result())
    source_finding = findings.get_finding(
        environment.project["id"], findings.list_findings(environment.project["id"])[0]["id"]
    )
    for corpus, nonce in [("synthetic-import-v1", "1"), ("synthetic-other-v1", "2")]:
        _import(environment, bundle_factory(corpus=corpus, nonce=nonce))
    rows = findings.list_findings(environment.project["id"])
    bac_rows = [row for row in rows if row["tool"] == "BAC"]
    assert len(bac_rows) == 2
    assert len({row["fingerprint"] for row in bac_rows}) == 2
    assert findings.get_finding(environment.project["id"], source_finding["id"]) == source_finding
    assert source_finding["last_seen_run_id"] == source
    _source_run(environment.project["id"], "source-after-import", {
        "ruff": [], "tools": [{"name": "Ruff", "status": "completed"}, {"name": "BAC", "status": "completed"}],
    })
    assert all(row["status"] == "open" for row in findings.list_findings(environment.project["id"]) if row["tool"] == "BAC")


def test_source_scan_comparison_ignores_intervening_research_run(environment, bundle_factory):
    source_result = _source_result()
    first = projects.create_scan_run(job_id="compare-first", project_id=environment.project["id"], requested_by=10, target="project", preset="quick")
    projects.update_scan_run(first, state="completed", progress=100, result=copy.deepcopy(source_result))
    _import(environment, bundle_factory())
    second = projects.create_scan_run(job_id="compare-second", project_id=environment.project["id"], requested_by=10, target="project", preset="quick")
    projects.update_scan_run(second, state="completed", progress=100, result=copy.deepcopy(source_result))
    assert projects.get_scan_run(second)["new_findings"] == 0


@pytest.mark.parametrize("with_source", [True, False])
def test_bounded_research_history_preserves_independent_latest_source_context(environment, monkeypatch, with_source):
    project_id = environment.project["id"]
    source_id = _source_run(project_id, "source-before-flood", _source_result()) if with_source else None
    result = json.dumps({"research_only": True, "gate_eligible": False,
                         "bac_report": {"status": "allowed", "exit_code": 0, "mode": "fixed"}})
    with database.get_connection() as connection:
        connection.executemany(
            """INSERT INTO scan_runs
               (job_id, project_id, requested_by, tenant_id, target, preset, state,
                progress, created_at, result_json)
               VALUES (?, ?, 10, 1, 'bac-research', 'quick', 'completed', 100, ?, ?)""",
            [(f"history-research-{index}", project_id, "2026-10-08T01:00:00+00:00", result) for index in range(55)],
        )
    with _client(environment, monkeypatch) as client:
        response = client.get(f"/api/projects/{project_id}/scans")
    assert response.status_code == 200, response.text
    history = response.json()
    assert len(history["scans"]) == 50
    assert all(run["run_kind"] == "bac_research" for run in history["scans"])
    if with_source:
        assert history["latest_source_scan"]["id"] == source_id
        assert history["latest_source_scan"]["run_kind"] == "source"
        assert history["latest_source_scan"]["target"] == "project"
    else:
        assert history["latest_source_scan"] is None


def test_identical_bundle_has_independent_project_and_tenant_identity(environment, bundle_factory):
    artifacts = bundle_factory()
    projects_to_import = [(environment.project, 10), (_project(), 10), (_project(20), 20)]
    runs = [projects.get_scan_run(_import(environment, artifacts, project=project, requested_by=user_id)["scan_run_id"])
            for project, user_id in projects_to_import]
    assert len({run["job_id"] for run in runs}) == 3
    assert len({run["id"] for run in runs}) == 3
    for run in runs:
        directory = environment.scans_root / "tenants" / str(run["tenant_id"]) / "projects" / str(run["project_id"]) / "runs" / run["job_id"]
        assert (directory / "report.json").read_bytes() == artifacts["report.json"]
        assert len(findings.list_findings(run["project_id"])) == 1


def test_service_rejects_cross_tenant_requester(environment, bundle_factory):
    with pytest.raises((ValueError, PermissionError)):
        _import(environment, bundle_factory(), requested_by=20)
    assert all(count == 0 for count in _counts().values())
    assert not [path for path in environment.scans_root.rglob("*") if path.is_file()]


def test_policy_simulation_rejects_completed_research_run(environment, bundle_factory):
    imported = _import(environment, bundle_factory(outcome="no_violation", mode="fixed"))
    with pytest.raises(ValueError, match="research|BAC|source"):
        policies.simulate_policy(environment.project["id"], imported["scan_run_id"], {"required_tools": []})


def test_retry_rejects_research_run_without_queuing(environment, bundle_factory, monkeypatch):
    imported = _import(environment, bundle_factory())
    monkeypatch.setattr(project_routes, "_enqueue_project_scan", lambda *args, **kwargs: pytest.fail("research report retry queued a source scan"))
    with pytest.raises(HTTPException) as error:
        project_routes.project_scan_retry(imported["scan_run_id"], principal=_principal())
    assert error.value.status_code in {400, 409}
    assert _counts()["scan_runs"] == 1


def test_http_import_returns_created_then_duplicate_and_research_history(environment, bundle_factory, monkeypatch):
    artifacts = bundle_factory()
    with _client(environment, monkeypatch) as client:
        url = f"/api/projects/{environment.project['id']}/bac-imports"
        first = client.post(url, files=_multipart(artifacts))
        second = client.post(url, files=_multipart(artifacts))
        assert first.status_code == 201, first.text
        assert second.status_code == 200, second.text
        assert second.json() == {**first.json(), "imported": False}
        assert first.json()["research_only"] is True
        history = client.get(f"/api/projects/{environment.project['id']}/scans")
        assert history.status_code == 200
        assert history.json()["scans"][0]["decision"] is None
        assert history.json()["scans"][0]["run_kind"] == "bac_research"


@pytest.mark.parametrize("principal,recent,expected", [
    (_principal(11, role="viewer"), True, 403),
    (_principal(12), True, 403),
    (_principal(13), True, 403),
    (_principal(20, tenant_id=2), True, 404),
    (_principal(), False, 403),
    (_principal(auth_method="token", scopes=("write",)), True, 403),
    (_principal(csrf_token="expected-csrf"), True, 403),
])
def test_http_import_requires_operator_membership_tenant_and_recent_auth(environment, bundle_factory, monkeypatch, principal, recent, expected):
    with _client(environment, monkeypatch, principal=principal, recent=recent) as client:
        response = client.post(f"/api/projects/{environment.project['id']}/bac-imports", files=_multipart(bundle_factory()))
    assert response.status_code == expected, response.text
    assert all(count == 0 for count in _counts().values())
    assert not environment.scans_root.exists()


def test_http_import_handles_bad_bundle_and_missing_pin(environment, bundle_factory, monkeypatch):
    def reject(*args):
        raise ValueError("Invalid BAC research bundle.")

    artifacts = bundle_factory()
    monkeypatch.setattr(environment.bac, "validate_bac_bundle", reject)
    with _client(environment, monkeypatch) as client:
        url = f"/api/projects/{environment.project['id']}/bac-imports"
        response = client.post(url, files=_multipart(artifacts))
        assert response.status_code == 400, response.text
        monkeypatch.delenv("AEGIS_BAC_IMPORT_PUBLIC_KEY")
        response = client.post(url, files=_multipart(artifacts))
        assert response.status_code == 503, response.text
    assert all(count == 0 for count in _counts().values())


@pytest.mark.parametrize("budget", ["AEGIS_MAX_ARTIFACT_BYTES", "AEGIS_MAX_TOTAL_ARTIFACT_BYTES"])
def test_http_import_bounds_uploaded_artifacts(environment, bundle_factory, monkeypatch, budget):
    artifacts = bundle_factory()
    monkeypatch.setenv(budget, "10")
    monkeypatch.setattr(environment.bac, "validate_bac_bundle", lambda *args: pytest.fail("oversized upload reached admission"))
    with _client(environment, monkeypatch) as client:
        response = client.post(f"/api/projects/{environment.project['id']}/bac-imports", files=_multipart(artifacts))
    assert response.status_code == 413, response.text
    assert all(count == 0 for count in _counts().values())
    assert not environment.scans_root.exists()


def test_http_import_rejects_duplicate_upload_names(environment, bundle_factory, monkeypatch):
    artifacts = bundle_factory()
    files = [*_multipart(artifacts), ("files", ("report.json", artifacts["report.json"], "application/json"))]
    with _client(environment, monkeypatch) as client:
        response = client.post(f"/api/projects/{environment.project['id']}/bac-imports", files=files)
    assert response.status_code == 400, response.text
    assert all(count == 0 for count in _counts().values())


def test_imported_artifact_routes_preserve_download_bytes_and_sandbox_html(environment, bundle_factory, monkeypatch):
    artifacts = bundle_factory()
    imported = _import(environment, artifacts)
    base = f"/api/projects/{environment.project['id']}/scans/{imported['scan_run_id']}/artifacts"
    with _client(environment, monkeypatch) as client:
        listing = client.get(base)
        assert listing.status_code == 200
        inventory = {item["name"]: item for item in listing.json()["artifacts"]}
        assert set(artifacts) <= set(inventory)
        assert all(inventory[name]["integrity"] == "verified" for name in artifacts)
        for name, content in artifacts.items():
            response = client.get(f"{base}/{name}")
            assert response.status_code == 200, response.text
            if name == "report.html":
                assert response.content.startswith(content)
                assert "sandbox" in response.headers["content-security-policy"]
                assert "allow-scripts" not in response.headers["content-security-policy"]
            else:
                assert response.content == content
        bundle = client.get(f"{base}/report-bundle.zip")
        assert bundle.status_code == 200, bundle.text
        with ZipFile(io.BytesIO(bundle.content)) as archive:
            assert set(archive.namelist()) == set(artifacts) | {"bundle-manifest.json"}
            assert all(archive.read(name) == content for name, content in artifacts.items())


@pytest.mark.parametrize("principal,expected", [
    (_principal(12), 403), (_principal(20, tenant_id=2), 404),
])
def test_imported_artifact_download_enforces_project_and_tenant_access(environment, bundle_factory, monkeypatch, principal, expected):
    imported = _import(environment, bundle_factory())
    url = f"/api/projects/{environment.project['id']}/scans/{imported['scan_run_id']}/artifacts/report.json"
    with _client(environment, monkeypatch, principal=principal) as client:
        response = client.get(url)
    assert response.status_code == expected, response.text


def test_imported_artifact_download_rejects_tampered_bytes(environment, bundle_factory, monkeypatch):
    imported = _import(environment, bundle_factory())
    run = projects.get_scan_run(imported["scan_run_id"])
    directory = artifact_storage.run_directory(environment.scans_root, run["job_id"], tenant_id=1, project_id=run["project_id"])
    path = directory / "report.json"
    original = path.read_bytes()
    path.write_bytes(b"X" + original[1:])
    with _client(environment, monkeypatch) as client:
        response = client.get(f"/api/projects/{environment.project['id']}/scans/{run['id']}/artifacts/report.json")
    assert response.status_code == 409, response.text


def test_imported_artifact_download_rejects_run_under_another_owned_project(environment, bundle_factory, monkeypatch):
    imported = _import(environment, bundle_factory())
    other = _project()
    with _client(environment, monkeypatch) as client:
        response = client.get(f"/api/projects/{other['id']}/scans/{imported['scan_run_id']}/artifacts/report.json")
    assert response.status_code == 404, response.text
