import json
from contextlib import contextmanager
from types import SimpleNamespace

import fastapi
import pytest

from app import database, projects
from app.routes import project_routes
from tests.test_projects import configure_project_database


def test_scan_history_selects_only_compact_summaries(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="API", repository_url="", github_full_name="", default_branch="main",
        scan_preset="standard", user_id=10,
    )
    run_id = projects.create_scan_run(
        job_id="large-report", project_id=project_id, requested_by=10, target="project", preset="standard",
    )
    result = {
        "policy": {"status": "BLOCKED", "reason": "Threshold exceeded.", "findings": ["x" * 50000]},
        "large_evidence": "y" * 50000,
        "finding_sync": {"created": 1, "reopened": 0},
    }
    projects.update_scan_run(run_id, state="completed", progress=100, result=result)
    statements = []
    real_connection = database.get_connection

    @contextmanager
    def traced_connection():
        with real_connection() as connection:
            class TracedConnection:
                def execute(self, sql, parameters=()):
                    statements.append(sql)
                    return connection.execute(sql, parameters)

            yield TracedConnection()

    monkeypatch.setattr(projects, "get_connection", traced_connection)
    history = projects.list_scan_runs(project_id)
    assert history[0]["decision"] == "BLOCKED"
    assert history[0]["failure_reason"] == "Threshold exceeded."
    assert all("result_json" not in sql for sql in statements)
    with real_connection() as connection:
        summary, full = connection.execute(
            "SELECT summary_json, result_json FROM scan_runs WHERE id = ?", (run_id,),
        ).fetchone()
    assert json.loads(summary) == {"policy": {"status": "BLOCKED", "reason": "Threshold exceeded."}}
    assert len(summary) < 200 and json.loads(full)["large_evidence"] == result["large_evidence"]


def test_scan_result_summary_retains_source_and_research_decisions_only():
    result = {
        "error": "Evidence missing.", "policy": {"status": "ERROR", "reason": "Cannot verify.", "extra": 1},
        "bac_report": {"status": "failed", "exit_code": 2, "mode": "reference", "findings": [1]},
        "other": "large payload",
    }
    assert projects.scan_result_summary(result) == {
        "error": "Evidence missing.", "policy": {"status": "ERROR", "reason": "Cannot verify."},
        "bac_report": {"status": "failed", "exit_code": 2, "mode": "reference"},
    }
    assert result["bac_report"]["findings"] == [1]
    assert projects.scan_result_summary({}) == {}


@pytest.mark.parametrize(
    ("user_id", "global_role", "tenant_id", "expected_status"),
    [(10, "operator", 1, None), (11, "viewer", 1, 403), (11, "admin", 1, None), (10, "admin", 2, 404)],
)
def test_project_access_uses_one_tenant_scoped_membership_query(
    tmp_path, monkeypatch, user_id, global_role, tenant_id, expected_status,
):
    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="API", repository_url="", github_full_name="", default_branch="main",
        scan_preset="standard", user_id=10,
    )
    statements = []
    real_connection = database.get_connection

    @contextmanager
    def traced_connection():
        with real_connection() as connection:
            class TracedConnection:
                def execute(self, sql, parameters=()):
                    statements.append(sql)
                    return connection.execute(sql, parameters)

            yield TracedConnection()

    monkeypatch.setattr(projects, "get_connection", traced_connection)
    principal = SimpleNamespace(user_id=user_id, role=global_role, tenant_id=tenant_id)
    if expected_status:
        with pytest.raises(fastapi.HTTPException) as error:
            project_routes._project_access(project_id, principal, "admin")
        assert error.value.status_code == expected_status
    else:
        assert project_routes._project_access(project_id, principal, "admin")["id"] == project_id
    assert len(statements) == 1


def test_project_access_preserves_missing_project_404(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    with pytest.raises(fastapi.HTTPException) as error:
        project_routes._project_access(99999, SimpleNamespace(user_id=10, role="admin", tenant_id=1), "viewer")
    assert error.value.status_code == 404


