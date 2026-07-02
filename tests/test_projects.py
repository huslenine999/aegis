from app import database
from app import github_integration
from app import notifications
from app import projects
from cryptography.fernet import Fernet
from urllib.parse import parse_qs, urlparse


def configure_project_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "projects.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(projects, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "USING_POSTGRES", False)
    database.initialize_database(reset=True)


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
