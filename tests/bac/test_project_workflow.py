"""Signed HTTP imports with real sessions, admission, SQLite, and artifact serving."""

import base64
from io import BytesIO
import json
from types import SimpleNamespace
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app import auth, bac_projects, database, findings, projects, web_common
from app.bac_imports import BAC_ARTIFACTS
from app.evidence import evidence_public_key
from app.routes import artifact_routes, project_routes
from app.security_middleware import RequestBodyLimitMiddleware, SecurityHeadersMiddleware
from test_import_validation import exported_bundle


@pytest.fixture
def workflow(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "test")
    monkeypatch.setenv("AEGIS_SESSION_SECRET", "test-bac-workflow-session-secret-long-enough")
    monkeypatch.setenv("AEGIS_TOKEN_PEPPER", "test-bac-workflow-token-pepper-long-enough")
    monkeypatch.setenv("AEGIS_ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("AEGIS_EVIDENCE_SIGNING_KEY", base64.urlsafe_b64encode(bytes(range(32))).decode())
    monkeypatch.setenv("AEGIS_BAC_IMPORT_PUBLIC_KEY", evidence_public_key()["public_key"])
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "workflow.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(projects, "USING_POSTGRES", False)
    monkeypatch.setattr(auth, "AUTH_REQUIRED", True)
    monkeypatch.setattr(web_common, "AUTH_REQUIRED", True)
    for module in (bac_projects, artifact_routes, project_routes):
        monkeypatch.setattr(module, "SCANS_DIR", tmp_path / "scans")
    database.initialize_database(reset=True)
    with database.get_connection() as connection:
        connection.execute("INSERT INTO tenants (id, slug, name, created_at) VALUES (2, 'other', 'Other', '2026-10-08')")
        connection.executemany(
            """INSERT INTO auth_users (id, tenant_id, username, password_hash, role, active, created_at)
               VALUES (?, ?, ?, 'unused', ?, 1, '2026-10-08')""",
            [(10, 1, "owner", "operator"), (11, 1, "viewer", "viewer"), (20, 2, "outsider", "operator")],
        )
    project_id = projects.create_project(name="BAC research", repository_url="", github_full_name="", default_branch="main", scan_preset="standard", user_id=10)
    projects.set_project_member(project_id, "viewer", "viewer")
    principals = {user_id: auth.Principal(user_id, name, role, f"csrf-{user_id}", tenant) for user_id, tenant, name, role in (
        (10, 1, "owner", "operator"), (11, 1, "viewer", "viewer"), (20, 2, "outsider", "operator"),
    )}
    sessions = {user_id: auth.create_session(principal) for user_id, principal in principals.items()}
    application = FastAPI()
    application.include_router(project_routes.router)
    application.include_router(artifact_routes.router)
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(RequestBodyLimitMiddleware, max_bytes=1024 * 1024)
    with TestClient(application) as client:
        yield SimpleNamespace(client=client, project_id=project_id, principals=principals, sessions=sessions, root=tmp_path)


def sign_in(workflow, user_id=10):
    workflow.client.cookies.clear()
    workflow.client.cookies.set(auth.SESSION_COOKIE, workflow.sessions[user_id])
    workflow.client.headers["X-CSRF-Token"] = workflow.principals[user_id].csrf_token


def uploaded(artifacts):
    return [("files", (name, content, BAC_ARTIFACTS[name])) for name, content in artifacts.items()]


@pytest.mark.parametrize("outcome,mode,state,count", [
    ("violation", "vulnerable", "completed", 1),
    ("no_violation", "fixed", "completed", 0),
    ("inconclusive", "vulnerable", "failed", 0),
])
def test_signed_authenticated_import_and_exact_download(workflow, outcome, mode, state, count):
    artifacts, _ = exported_bundle(workflow.root / "export", outcome=outcome, mode=mode)
    sign_in(workflow)
    url = f"/api/projects/{workflow.project_id}/bac-imports"
    response = workflow.client.post(url, files=uploaded(artifacts))
    assert response.status_code == 201, response.text
    run_id = response.json()["scan_run_id"]
    duplicate = workflow.client.post(url, files=uploaded(artifacts))
    assert duplicate.status_code == 200
    assert duplicate.json() == {**response.json(), "imported": False}
    run = workflow.client.get(f"/api/projects/{workflow.project_id}/scans/{run_id}").json()
    assert run["state"] == state
    assert run["result"]["research_only"] is True
    assert run["result"]["gate_eligible"] is False
    assert run["policy_version_id"] is None
    findings = workflow.client.get(f"/api/projects/{workflow.project_id}/findings").json()["findings"]
    assert len(findings) == count
    assert all(item["tool"] == "BAC" and item["occurrence_count"] == 1 for item in findings)
    base = f"/api/projects/{workflow.project_id}/scans/{run_id}/artifacts"
    evidence = workflow.client.get(f"{base}/report-bundle.zip")
    assert evidence.status_code == 200, evidence.text
    with zipfile.ZipFile(BytesIO(evidence.content)) as archive:
        for name, content in artifacts.items():
            assert archive.read(name) == content
    html = workflow.client.get(f"{base}/report.html")
    assert html.status_code == 200
    assert "sandbox; default-src 'none'" in html.headers["Content-Security-Policy"]
    assert html.content.startswith(artifacts["report.html"])
    manifest = workflow.client.get(f"{base}/scan-manifest.json")
    assert manifest.content == artifacts["scan-manifest.json"]
    with database.get_connection() as connection:
        assert connection.execute("SELECT count(*) FROM audit_events WHERE action = 'research.bac_imported'").fetchone()[0] == 1


def test_signed_http_import_rejects_tampering_and_unknown_signer(workflow, monkeypatch):
    artifacts, _ = exported_bundle(workflow.root / "export")
    sign_in(workflow)
    url = f"/api/projects/{workflow.project_id}/bac-imports"
    tampered = workflow.client.post(url, files=uploaded({**artifacts, "report.json": b"{}"}))
    assert tampered.status_code == 400
    monkeypatch.setenv("AEGIS_EVIDENCE_SIGNING_KEY", base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode())
    unknown, _ = exported_bundle(workflow.root / "unknown")
    untrusted = workflow.client.post(url, files=uploaded(unknown))
    assert untrusted.status_code == 400
    assert projects.list_scan_runs(workflow.project_id) == []
    assert not (workflow.root / "scans").exists()


def test_real_session_csrf_roles_tenants_and_artifact_access(workflow):
    artifacts, _ = exported_bundle(workflow.root / "export")
    url = f"/api/projects/{workflow.project_id}/bac-imports"
    assert workflow.client.post(url, files=uploaded(artifacts)).status_code == 401
    sign_in(workflow)
    workflow.client.headers.pop("X-CSRF-Token")
    assert workflow.client.post(url, files=uploaded(artifacts)).status_code == 403
    sign_in(workflow, 11)
    assert workflow.client.post(url, files=uploaded(artifacts)).status_code == 403
    sign_in(workflow, 20)
    assert workflow.client.post(url, files=uploaded(artifacts)).status_code == 404
    sign_in(workflow)
    imported = workflow.client.post(url, files=uploaded(artifacts))
    assert imported.status_code == 201
    run_id = imported.json()["scan_run_id"]
    artifact = f"/api/projects/{workflow.project_id}/scans/{run_id}/artifacts/evidence.json"
    sign_in(workflow, 11)
    assert workflow.client.get(artifact).content == artifacts["evidence.json"]
    sign_in(workflow, 20)
    assert workflow.client.get(artifact).status_code == 404
    sign_in(workflow)
    with database.get_connection() as connection:
        connection.execute("UPDATE auth_sessions SET authenticated_at = '2020-01-01T00:00:00+00:00' WHERE user_id = 10")
    recent = workflow.client.post(url, files=uploaded(artifacts))
    assert recent.status_code == 403
    assert "Recent authentication" in recent.json()["detail"]


def research_state():
    tables = ("scan_runs", "scan_artifacts", "security_findings", "finding_occurrences", "finding_events", "audit_events")
    with database.get_connection() as connection:
        return {table: connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall() for table in tables}


def test_bac_finding_review_identifies_exact_latest_occurrence_without_changing_triage(workflow):
    artifacts, _ = exported_bundle(workflow.root / "first-export")
    sign_in(workflow)
    base = f"/api/projects/{workflow.project_id}"
    first = workflow.client.post(f"{base}/bac-imports", files=uploaded(artifacts))
    assert first.status_code == 201
    finding = workflow.client.get(f"{base}/findings").json()["findings"][0]
    assert "research_case" not in finding
    first_detail = workflow.client.get(f"{base}/findings/{finding['id']}").json()
    assert first_detail["research_case"] == {
        "scan_run_id": first.json()["scan_run_id"], "case_id": "cross-owner",
        "actor": "alice", "operation": "read", "resource": "bob-private-1",
    }
    triaged = workflow.client.patch(f"{base}/findings/{finding['id']}", json={
        "status": "resolved", "resolution_note": "Manually reviewed synthetic experiment.",
    })
    assert triaged.status_code == 200
    matrix = json.loads(artifacts["matrix.json"])
    cases = [{**case, "id": "renamed-cross-owner"} if case["id"] == "cross-owner" else case for case in matrix["cases"]]
    newer, _ = exported_bundle(workflow.root / "second-export", cases=cases)
    second = workflow.client.post(f"{base}/bac-imports", files=uploaded(newer))
    assert second.status_code == 201
    before = research_state()
    sign_in(workflow, 11)
    detail = workflow.client.get(f"{base}/findings/{finding['id']}").json()
    assert detail["research_case"] == {
        "scan_run_id": second.json()["scan_run_id"], "case_id": "renamed-cross-owner",
        "actor": "alice", "operation": "read", "resource": "bob-private-1",
    }
    assert detail["status"] == "resolved"
    assert detail["occurrence_count"] == 2
    assert research_state() == before


@pytest.mark.parametrize("outcome", ["violation", "no_violation", "inconclusive"])
def test_viewer_review_reads_all_original_cases_and_evidence_without_writes(workflow, outcome):
    artifacts, _ = exported_bundle(workflow.root / "review-export", outcome=outcome, split="all")
    sign_in(workflow)
    base = f"/api/projects/{workflow.project_id}"
    imported = workflow.client.post(f"{base}/bac-imports", files=uploaded(artifacts))
    assert imported.status_code == 201
    run_id = imported.json()["scan_run_id"]
    before = research_state()
    sign_in(workflow, 11)
    workflow.client.headers.pop("X-CSRF-Token")
    detail = workflow.client.get(f"{base}/scans/{run_id}")
    assert detail.status_code == 200
    assert detail.json()["run_kind"] == "bac_research"
    assert detail.json()["result"]["gate_eligible"] is False
    assert detail.json()["policy_version_id"] is None
    original = workflow.client.get(f"{base}/scans/{run_id}/artifacts/report.json")
    assert original.status_code == 200
    assert original.content == artifacts["report.json"]
    report = original.json()
    assert report["run_id"] == detail.json()["result"]["bac_report"]["run_id"]
    assert [case["id"] for case in report["results"]] == ["cross-owner", "allowed-owner", "guest-preview"]
    assert [case["status"] for case in report["results"]] == [outcome, "no_violation", "no_violation"]
    for name in ("evidence.json", "server-events.json", "matrix.json", "scan-manifest.json"):
        response = workflow.client.get(f"{base}/scans/{run_id}/artifacts/{name}")
        assert response.status_code == 200
        assert response.content == artifacts[name]
    assert research_state() == before


def test_source_findings_do_not_receive_bac_case_links(workflow):
    run_id = projects.create_scan_run(
        job_id="source-review", project_id=workflow.project_id, requested_by=10, target="project", preset="standard",
    )
    result = {"ruff": [{"code": "S102", "message": "Avoid exec", "filename": "synthetic.py", "location": {"row": 1}}]}
    findings.sync_findings(run_id, result)
    sign_in(workflow, 11)
    base = f"/api/projects/{workflow.project_id}"
    finding = workflow.client.get(f"{base}/findings").json()["findings"][0]
    detail = workflow.client.get(f"{base}/findings/{finding['id']}")
    assert detail.status_code == 200
    assert "research_case" not in detail.json()


@pytest.mark.parametrize("mismatch", ["missing-occurrence", "source-run", "other-project"])
def test_research_case_link_fails_closed_when_latest_occurrence_is_not_owned_research(workflow, mismatch):
    artifacts, _ = exported_bundle(workflow.root / "occurrence-export")
    sign_in(workflow)
    base = f"/api/projects/{workflow.project_id}"
    workflow.client.post(f"{base}/bac-imports", files=uploaded(artifacts))
    finding = workflow.client.get(f"{base}/findings").json()["findings"][0]
    if mismatch == "missing-occurrence":
        with database.get_connection() as connection:
            connection.execute("DELETE FROM finding_occurrences WHERE finding_id = ?", (finding["id"],))
    else:
        other_project = projects.create_project(name="Occurrence boundary", repository_url="", github_full_name="", default_branch="main", scan_preset="quick", user_id=10)
        project_id = other_project if mismatch == "other-project" else workflow.project_id
        run_id = projects.create_scan_run(
            job_id=f"mismatched-{mismatch}", project_id=project_id, requested_by=10,
            target="bac-research" if mismatch == "other-project" else "project", preset="quick",
        )
        with database.get_connection() as connection:
            raw = connection.execute("SELECT raw_json FROM finding_occurrences WHERE finding_id = ?", (finding["id"],)).fetchone()[0]
            connection.execute("INSERT INTO finding_occurrences (finding_id, scan_run_id, raw_json, observed_at) VALUES (?, ?, ?, '2026-10-08')", (finding["id"], run_id, raw))
            connection.execute("UPDATE security_findings SET last_seen_run_id = ? WHERE id = ?", (run_id, finding["id"]))
    sign_in(workflow, 11)
    detail = workflow.client.get(f"{base}/findings/{finding['id']}")
    assert detail.status_code == 200
    assert detail.json()["research_case"] is None


def test_research_case_links_and_raw_evidence_respect_project_and_tenant_boundaries(workflow):
    artifacts, _ = exported_bundle(workflow.root / "boundary-export")
    sign_in(workflow)
    base = f"/api/projects/{workflow.project_id}"
    imported = workflow.client.post(f"{base}/bac-imports", files=uploaded(artifacts)).json()
    finding = workflow.client.get(f"{base}/findings").json()["findings"][0]
    paths = (f"findings/{finding['id']}", f"scans/{imported['scan_run_id']}", f"scans/{imported['scan_run_id']}/artifacts/report.json")
    sign_in(workflow, 20)
    for path in paths:
        assert workflow.client.get(f"{base}/{path}").status_code == 404
    projects.remove_project_member(workflow.project_id, 11)
    sign_in(workflow, 11)
    for path in paths:
        assert workflow.client.get(f"{base}/{path}").status_code == 403
    sign_in(workflow)
    other = projects.create_project(name="Other research", repository_url="", github_full_name="", default_branch="main", scan_preset="quick", user_id=10)
    for path in paths:
        assert workflow.client.get(f"/api/projects/{other}/{path}").status_code == 404
    workflow.client.cookies.clear()
    workflow.client.headers.pop("X-CSRF-Token")
    for path in paths:
        assert workflow.client.get(f"{base}/{path}").status_code == 401


def test_case_review_cannot_read_tampered_original_report(workflow):
    artifacts, _ = exported_bundle(workflow.root / "tamper-export")
    sign_in(workflow)
    base = f"/api/projects/{workflow.project_id}"
    run_id = workflow.client.post(f"{base}/bac-imports", files=uploaded(artifacts)).json()["scan_run_id"]
    job_id = projects.get_scan_run(run_id)["job_id"]
    report_path = workflow.root / "scans" / "tenants" / "1" / "projects" / str(workflow.project_id) / "runs" / job_id / "report.json"
    report_path.write_bytes(artifacts["report.json"].replace(b"synthetic-run-1", b"synthetic-run-X"))
    sign_in(workflow, 11)
    response = workflow.client.get(f"{base}/scans/{run_id}/artifacts/report.json")
    assert response.status_code == 409
    assert "integrity" in response.json()["detail"].lower()


@pytest.mark.parametrize("status,severity,response_status,count", [
    ("open", "high", 200, 1), ("resolved", "HIGH", 200, 0),
    ("unsupported", "HIGH", 400, None), ("open", "unsupported", 400, None),
])
def test_bac_review_finding_filters_preserve_authorized_lookup(workflow, status, severity, response_status, count):
    artifacts, _ = exported_bundle(workflow.root / "filter-export")
    sign_in(workflow)
    base = f"/api/projects/{workflow.project_id}"
    workflow.client.post(f"{base}/bac-imports", files=uploaded(artifacts))
    sign_in(workflow, 11)
    response = workflow.client.get(f"{base}/findings", params={"status": status, "severity": severity})
    assert response.status_code == response_status
    if response_status == 200:
        result = response.json()["findings"]
        assert len(result) == count
        assert all(item["tool"] == "BAC" and item["severity"] == "HIGH" for item in result)
