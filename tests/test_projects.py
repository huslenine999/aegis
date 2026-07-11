from app import database
from app import github_integration
from app import notifications
from app import projects
from app import main as app_main
from app import worker
from cryptography.fernet import Fernet
from urllib.parse import parse_qs, urlparse
import pytest


def configure_project_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "projects.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(projects, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "USING_POSTGRES", False)
    database.initialize_database(reset=True)
    with database.get_connection() as connection:
        connection.executemany(
            """INSERT INTO auth_users
               (id, username, password_hash, role, active, created_at)
               VALUES (?, ?, ?, ?, 1, ?)""",
            [
                (7, "github-user", "unused", "operator", "2026-01-01T00:00:00+00:00"),
                (10, "owner", "unused", "operator", "2026-01-01T00:00:00+00:00"),
                (11, "viewer", "unused", "viewer", "2026-01-01T00:00:00+00:00"),
            ],
        )


def test_projects_are_membership_scoped(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="API",
        repository_url="https://github.com/example/api.git",
        github_full_name="example/api",
        default_branch="main",
        scan_preset="standard",
        user_id=10,
    )

    owner_projects = projects.list_projects(10, "operator")
    assert owner_projects[0]["id"] == project_id
    assert owner_projects[0]["role"] == "admin"
    assert projects.list_projects(11, "operator") == []
    assert projects.project_role(project_id, 10, "operator") == "admin"


def test_scan_history_tracks_new_findings_against_previous_run(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="API",
        repository_url="",
        github_full_name="",
        default_branch="main",
        scan_preset="quick",
        user_id=10,
    )
    first = projects.create_scan_run(
        job_id="job-1",
        project_id=project_id,
        requested_by=10,
        target="project",
        preset="quick",
    )
    projects.update_scan_run(
        first,
        state="completed",
        progress=100,
        result={"ruff": [{"code": "S307", "filename": "a.py", "location": {"row": 1}}]},
    )
    assert projects.get_scan_run(first)["new_findings"] == 1

    second = projects.create_scan_run(
        job_id="job-2",
        project_id=project_id,
        requested_by=10,
        target="project",
        preset="quick",
    )
    projects.update_scan_run(
        second,
        state="completed",
        progress=100,
        result={
            "ruff": [
                {"code": "S307", "filename": "a.py", "location": {"row": 1}},
                {"code": "S105", "filename": "b.py", "location": {"row": 2}},
            ]
        },
    )

    latest = projects.get_scan_run(second)
    assert latest["new_findings"] == 1
    assert [run["id"] for run in projects.list_scan_runs(project_id)] == [second, first]


def test_fingerprints_cover_every_scanner_family_and_ignore_line_moves():
    first = {
        "ruff": [{"code": "S105", "filename": "a.py", "message": "secret", "location": {"row": 1}}],
        "secrets": {"results": {"a.py": [{"type": "API Key", "line_number": 4}]}},
        "yara": [{"rule": "Webshell", "filename": "a.py"}],
        "trivy": {"Results": [{"Target": "image", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "lib"}]}]},
    }
    moved = {
        **first,
        "ruff": [{"code": "S105", "filename": "a.py", "message": "secret", "location": {"row": 99}}],
        "secrets": {"results": {"a.py": [{"type": "API Key", "line_number": 99}]}},
    }
    assert projects._fingerprints(first) == projects._fingerprints(moved)
    assert len(projects._fingerprints(first)) == 4


def test_project_scan_artifacts_are_run_scoped(tmp_path, monkeypatch):
    scans_dir = tmp_path / "scans"
    run_dir = scans_dir / "runs" / "job-1"
    run_dir.mkdir(parents=True)
    (run_dir / "report.html").write_text("<h1>Project report</h1>")
    (run_dir / "sbom.json").write_text("{}")
    monkeypatch.setattr(app_main, "SCANS_DIR", scans_dir)
    monkeypatch.setattr(app_main, "_project_access", lambda *args: {"id": 7})
    monkeypatch.setattr(
        app_main,
        "get_scan_run",
        lambda run_id: {"id": run_id, "project_id": 7, "job_id": "job-1"},
    )

    listing = app_main.project_scan_artifacts(7, 3, principal=object())
    assert {item["name"] for item in listing["artifacts"]} == {
        "report.html",
        "sbom.json",
        "report-bundle.zip",
    }
    response = app_main.project_scan_artifact(
        7, 3, "report.html", principal=object()
    )
    assert response.path == str(run_dir / "report.html")


def test_deep_project_scan_fails_closed_without_isolated_runtime(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    target = tmp_path / "target"
    target.mkdir()
    (target / "safe.py").write_text("def add(left, right):\n    return left + right\n")
    scans_dir = tmp_path / "scans"
    project_id = projects.create_project(
        name="Deep audit",
        repository_url="",
        github_full_name="",
        default_branch="main",
        scan_preset="deep",
        user_id=10,
    )
    run_id = projects.create_scan_run(
        job_id="deep-job",
        project_id=project_id,
        requested_by=10,
        target="project",
        preset="deep",
    )
    monkeypatch.setattr(worker, "SCANS_DIR", scans_dir)
    monkeypatch.setattr(worker, "PROJECT_ROOT", target)
    monkeypatch.setattr(worker, "get_project", projects.get_project)
    monkeypatch.setattr(worker, "update_scan_run", projects.update_scan_run)
    monkeypatch.setattr(worker, "is_docker_available", lambda: False)
    monkeypatch.setattr(worker, "run_yara_scan", lambda *args: [])
    monkeypatch.setattr(worker, "run_clamav_scan", lambda *args: [])
    monkeypatch.setattr(worker, "stop_and_cleanup_sandbox", lambda *args: None)
    monkeypatch.setattr(worker.time, "sleep", lambda *args: None)

    with pytest.raises(worker.ScanOperationalFailure):
        worker.async_scan_task(
            "deep-job",
            "project",
            scan_run_id=run_id,
            project_id=project_id,
            requested_by=10,
            preset="deep",
        )

    failed = projects.get_scan_run(run_id)
    assert failed["state"] == "failed"
    assert set(failed["result"]["operational_failures"]) >= {
        "Docker Sandbox",
        "DAST",
        "Trivy",
    }


def test_test_mode_legacy_scan_does_not_launch_docker(tmp_path, monkeypatch):
    scans_dir = tmp_path / "scans"
    target = tmp_path / "target"
    target.mkdir()
    (target / "safe.py").write_text("def add(left, right):\n    return left + right\n")
    monkeypatch.setenv("AEGIS_SKIP_EXTERNAL_SCANNERS", "true")
    monkeypatch.setattr(worker, "SCANS_DIR", scans_dir)
    monkeypatch.setattr(worker, "PROJECT_ROOT", target)
    monkeypatch.setattr(worker, "run_yara_scan", lambda *args: [])
    monkeypatch.setattr(worker, "run_clamav_scan", lambda *args: [])
    docker_checks = []
    monkeypatch.setattr(
        worker,
        "is_docker_available",
        lambda: docker_checks.append(True) or True,
    )
    monkeypatch.setattr(
        worker,
        "build_sandbox_image",
        lambda *args: pytest.fail("test-mode scan attempted to build a container"),
    )
    monkeypatch.setattr(worker.time, "sleep", lambda *args: None)

    worker.async_scan_task("legacy-job", "secure")

    manifest = (scans_dir / "runs" / "legacy-job" / "scan-manifest.json").read_text()
    assert '"policy_status": "ALLOWED"' in manifest
    assert docker_checks == [True]


def test_github_oauth_uses_pkce_and_encrypts_token(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    monkeypatch.setattr(
        github_integration, "get_connection", database.get_connection
    )
    monkeypatch.setenv("AEGIS_GITHUB_CLIENT_ID", "client-id")
    monkeypatch.setenv("AEGIS_GITHUB_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", Fernet.generate_key().decode())

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
        lambda *args, **kwargs: Response(
            {"access_token": "secret-github-token", "scope": "repo read:user"}
        ),
    )

    def fake_get(url, **kwargs):
        if url.endswith("/user"):
            return Response({"login": "octocat"})
        return Response(
            [
                {
                    "id": 1,
                    "full_name": "octocat/aegis",
                    "name": "aegis",
                    "private": True,
                    "clone_url": "https://github.com/octocat/aegis.git",
                    "default_branch": "main",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ]
        )

    monkeypatch.setattr(github_integration.requests, "get", fake_get)

    authorization_url = github_integration.begin_oauth(
        7, "https://aegis.example.com/api/github/callback"
    )
    query = parse_qs(urlparse(authorization_url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"]
    assert query["code_challenge"]

    assert github_integration.complete_oauth(
        "oauth-code",
        query["state"][0],
        "https://aegis.example.com/api/github/callback",
    ) == 7
    assert github_integration.github_connection(7)["login"] == "octocat"
    assert github_integration.github_token(7) == "secret-github-token"
    assert github_integration.list_repositories(7)[0]["full_name"] == "octocat/aegis"


def test_notification_configuration_is_encrypted_and_delivered(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    monkeypatch.setattr(notifications, "get_connection", database.get_connection)
    monkeypatch.setattr(notifications, "_validate_webhook_url", lambda url: None)
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    project_id = projects.create_project(
        name="API",
        repository_url="",
        github_full_name="",
        default_branch="main",
        scan_preset="standard",
        user_id=10,
    )
    channel_id = notifications.create_channel(
        project_id=project_id,
        name="Security",
        channel_type="slack",
        config={"url": "https://hooks.slack.com/services/secret"},
        events=["blocked", "failed"],
        created_by=10,
    )
    channels = notifications.list_channels(project_id)
    assert channels == [
        {
            "id": channel_id,
            "name": "Security",
            "channel_type": "slack",
            "events": ["blocked", "failed"],
            "enabled": True,
            "created_at": channels[0]["created_at"],
        }
    ]
    with database.get_connection() as connection:
        encrypted = connection.execute(
            "SELECT config_encrypted FROM notification_channels WHERE id = ?",
            (channel_id,),
        ).fetchone()[0]
    assert "hooks.slack.com" not in encrypted

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

    delivered = []
    monkeypatch.setattr(
        notifications.requests,
        "post",
        lambda *args, **kwargs: delivered.append((args, kwargs)) or Response(),
    )
    notifications.send_project_notification(
        project_id, "blocked", {"project_name": "API", "job_id": "job-1"}
    )
    assert len(delivered) == 1
    with database.get_connection() as connection:
        status = connection.execute(
            "SELECT status FROM notification_deliveries WHERE channel_id = ?",
            (channel_id,),
        ).fetchone()[0]
    assert status == "delivered"


def test_webhook_delivery_rejects_redirects(monkeypatch):
    monkeypatch.setattr(notifications, "_validate_webhook_url", lambda url: None)
    monkeypatch.setattr(notifications.time, "sleep", lambda seconds: None)

    class Redirect:
        status_code = 302

        def raise_for_status(self):
            return None

    attempts = []
    monkeypatch.setattr(
        notifications.requests,
        "post",
        lambda *args, **kwargs: attempts.append(kwargs) or Redirect(),
    )
    with pytest.raises(RuntimeError, match="redirects are not allowed"):
        notifications._post_with_retries("https://example.com/hook", json={})
    assert len(attempts) == 3
    assert all(attempt["allow_redirects"] is False for attempt in attempts)
