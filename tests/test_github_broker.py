"""The GitHub credential broker acts only for in-flight runs, scoped to their repository."""

import base64
import os

import pytest

from app import database, github_broker, github_broker_entrypoint, github_integration, github_lifecycle, projects, worker
from app.github_broker import BrokerRefused, complete_run_check, issue_clone_token
from tests.test_projects import configure_project_database


@pytest.fixture
def runs(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="Brokered", repository_url="https://github.com/example/api", github_full_name="example/api",
        default_branch="main", scan_preset="quick", user_id=10,
    )
    # Bind the repository to installation 55, as the first verified webhook does.
    github_lifecycle.resolve_github_webhook_binding(
        repository_full_name="example/api", repository_id=101, installation_id=55,
    )
    app_run = projects.create_scan_run(
        job_id="app-run", project_id=project_id, requested_by=10, target="project", preset="quick",
        github_installation_id=55, github_check_run_id=77,
    )
    oauth_run = projects.create_scan_run(
        job_id="oauth-run", project_id=project_id, requested_by=7, target="project", preset="quick",
    )
    with database.get_connection() as connection:
        tenant_id = connection.execute("SELECT tenant_id FROM projects WHERE id = ?", (project_id,)).fetchone()[0]
    minted, oauth, checks = [], [], []
    monkeypatch.setattr(
        github_broker, "github_installation_token",
        lambda installation_id, **kwargs: minted.append((installation_id, kwargs)) or "ghs_scoped",
    )
    monkeypatch.setattr(github_broker, "github_token", lambda user_id: oauth.append(user_id) or "gho_user")
    monkeypatch.setattr(
        github_broker, "complete_check_run",
        lambda *args, **kwargs: checks.append((args, kwargs)),
    )
    return type("Runs", (), {
        "app": app_run, "oauth": oauth_run, "tenant_id": tenant_id,
        "minted": minted, "oauth_users": oauth, "checks": checks,
    })


def test_clone_token_is_scoped_to_the_runs_repository_and_read_only(runs):
    assert issue_clone_token({"scan_run_id": runs.app}) == {"token": "ghs_scoped", "kind": "installation"}
    assert runs.minted == [(55, {
        "tenant_id": runs.tenant_id, "repository": "example/api", "permissions": {"contents": "read"},
    })]


def test_oauth_clone_uses_the_recorded_requester_not_the_caller(runs):
    assert issue_clone_token({"scan_run_id": runs.oauth}) == {"token": "gho_user", "kind": "oauth"}
    assert runs.oauth_users == [7]


@pytest.mark.parametrize("request_body", [
    {"scan_run_id": 1, "repository": "victim/private"},
    {"scan_run_id": 1, "user_id": 1},
    {},
    {"scan_run_id": "1"},
    {"scan_run_id": True},
    {"scan_run_id": 0},
    {"scan_run_id": 999},
    "scan_run_id=1",
])
def test_clone_requests_cannot_choose_what_they_get(runs, request_body):
    with pytest.raises(BrokerRefused):
        issue_clone_token(request_body)
    assert runs.minted == [] and runs.oauth_users == []


def test_finished_runs_get_no_credentials(runs):
    projects.update_scan_run(runs.app, state="completed", progress=100, result={"ok": True})

    with pytest.raises(BrokerRefused, match="still in progress"):
        issue_clone_token({"scan_run_id": runs.app})


def test_check_completion_targets_the_runs_own_check(runs):
    assert complete_run_check({
        "scan_run_id": runs.app, "conclusion": "failure", "title": "Blocked", "summary": "One finding",
    }) == {"completed": True}

    (args, kwargs), = runs.checks
    assert args == (55, "example/api", 77)
    assert kwargs["conclusion"] == "failure" and kwargs["tenant_id"] == runs.tenant_id


@pytest.mark.parametrize("request_body", [
    {"scan_run_id": 1, "conclusion": "approved"},
    {"scan_run_id": 1, "conclusion": "success", "repository": "victim/private"},
    {"scan_run_id": 1, "conclusion": "success", "check_run_id": 1},
    {"scan_run_id": 1, "conclusion": "success", "annotations": "not-a-list"},
    {"conclusion": "success"},
])
def test_check_requests_cannot_redirect_or_invent_outcomes(runs, request_body):
    with pytest.raises(BrokerRefused):
        complete_run_check(request_body)
    assert runs.checks == []


def test_runs_without_a_github_check_are_a_no_op(runs):
    assert complete_run_check({"scan_run_id": runs.oauth, "conclusion": "success"}) == {"completed": False}
    assert runs.checks == []


def test_remote_mode_sends_only_the_run_id_to_the_broker_queue(runs, monkeypatch):
    calls = []
    monkeypatch.setenv("AEGIS_GITHUB_BROKER", "remote")
    monkeypatch.setattr(
        github_broker, "call_service",
        lambda queue, function, request, **kwargs: calls.append((queue, function, request)) or {"token": "t"},
    )

    assert github_broker.clone_token(runs.app) == "t"
    assert calls == [("github-credentials", "clone_token", {"scan_run_id": runs.app})]


def test_worker_clones_with_the_brokered_token_and_never_without_a_run(runs, tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(worker.shutil, "which", lambda name: "/usr/bin/git")
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs.get("env", {})))
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(worker, "run_bounded_subprocess", run)
    project = projects.get_project(1)

    worker._clone_github_project(project, 10, "app-run", 55, None, runs.app)

    header = commands[0][1]["GIT_CONFIG_VALUE_0"]
    assert base64.b64decode(header.split()[-1]).decode() == "x-access-token:ghs_scoped"

    monkeypatch.setenv("AEGIS_GITHUB_BROKER", "remote")
    with pytest.raises(RuntimeError, match="recorded scan run"):
        worker._clone_github_project(project, 10, "legacy", 55, None, None)


def test_installation_tokens_request_one_repository_and_named_permissions(monkeypatch):
    sent = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"token": "ghs_scoped"}

    monkeypatch.setattr(github_integration, "require_active_github_binding", lambda **kwargs: {})
    monkeypatch.setattr(github_integration, "github_app_jwt", lambda: "jwt")
    monkeypatch.setattr(github_integration.requests, "post", lambda url, **kwargs: sent.update(kwargs) or Response())

    github_integration.github_installation_token(
        55, tenant_id=1, repository="example/api", permissions={"contents": "read"},
    )

    assert sent["json"] == {"repositories": ["api"], "permissions": {"contents": "read"}}


def test_broker_holds_only_github_and_credential_secrets_in_production(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_ENCRYPTION_KEY is required"):
        github_broker_entrypoint.validate_broker_configuration()

    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    github_broker_entrypoint.validate_broker_configuration()
    for secret in ("AEGIS_EVIDENCE_SIGNING_KEY", "AEGIS_SESSION_SECRET", "AEGIS_SMTP_PASSWORD"):
        monkeypatch.setenv(secret, "must-not-reach-broker")
        with pytest.raises(RuntimeError, match=secret):
            github_broker_entrypoint.validate_broker_configuration()
        monkeypatch.delenv(secret)
