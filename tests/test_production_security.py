from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth
from app import database
from app.config import validate_server_bind
from app.database import InMemoryRedis
from app.rate_limit import RateLimitMiddleware, allow_websocket
from app.security_middleware import RequestBodyLimitMiddleware


def test_password_hashes_are_salted_and_verified():
    first = auth.hash_password("correct horse battery staple")
    second = auth.hash_password("correct horse battery staple")

    assert first != second
    assert auth.verify_password("correct horse battery staple", first)
    assert not auth.verify_password("wrong password", first)


def test_server_session_rejects_tampering_and_can_be_revoked(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "sessions.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(auth, "get_connection", database.get_connection)
    database.initialize_database(reset=True)
    with database.get_connection() as connection:
        connection.execute(
            """INSERT INTO auth_users
               (id, username, password_hash, role, active, created_at)
               VALUES (?, ?, ?, ?, 1, ?)""",
            (7, "operator", auth.hash_password("a sufficiently long password"), "operator", "2026-01-01T00:00:00+00:00"),
        )
    principal = auth.Principal(7, "operator", "operator", "csrf")
    session = auth.create_session(principal)
    tampered = ("A" if session[0] != "A" else "B") + session[1:]

    assert auth._decode_session(session) == principal
    assert auth._decode_session(tampered) is None
    auth.revoke_session(session)
    assert auth._decode_session(session) is None

    refreshed = auth.create_session(principal)
    with database.get_connection() as connection:
        connection.execute("UPDATE auth_users SET role = 'viewer' WHERE id = 7")
    assert auth._decode_session(refreshed).role == "viewer"
    with database.get_connection() as connection:
        connection.execute("UPDATE auth_users SET active = 0 WHERE id = 7")
    assert auth._decode_session(refreshed) is None


def test_http_rate_limit_returns_retry_after(monkeypatch):
    monkeypatch.setenv("AEGIS_RATE_LIMIT_PER_MINUTE", "2")
    application = FastAPI()

    @application.get("/protected")
    def protected():
        return {"ok": True}

    application.add_middleware(RateLimitMiddleware, redis_client=InMemoryRedis())
    client = TestClient(application)

    assert client.get("/protected").status_code == 200
    assert client.get("/protected").status_code == 200
    limited = client.get("/protected")
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"


def test_production_mutations_fail_closed_when_rate_limit_store_is_down(monkeypatch):
    class BrokenRedis:
        def incr(self, key):
            raise ConnectionError("redis unavailable")

    monkeypatch.setenv("AEGIS_ENV", "production")
    application = FastAPI()

    @application.post("/mutate")
    def mutate():
        return {"ok": True}

    application.add_middleware(RateLimitMiddleware, redis_client=BrokenRedis())
    response = TestClient(application).post("/mutate")

    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
    assert allow_websocket(BrokenRedis(), "127.0.0.1") is False


def test_scanner_subprocess_environment_excludes_application_secrets(monkeypatch):
    from app.scanners import scanner_subprocess_environment

    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("AEGIS_ENCRYPTION_KEY", "secret")

    environment = scanner_subprocess_environment()

    assert environment["PATH"] == "/usr/bin"
    assert "DATABASE_URL" not in environment
    assert "AEGIS_ENCRYPTION_KEY" not in environment


def test_request_body_limit_rejects_before_route_parsing():
    application = FastAPI()

    @application.post("/upload")
    async def upload():
        return {"ok": True}

    application.add_middleware(RequestBodyLimitMiddleware, max_bytes=8)
    response = TestClient(application).post("/upload", content=b"0123456789")
    assert response.status_code == 413


def test_initial_setup_rotates_admin_and_persists_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "setup.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(auth, "get_connection", database.get_connection)
    monkeypatch.setenv("AEGIS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "temporary-password")
    database.initialize_database(reset=True)
    auth.ensure_bootstrap_admin()

    principal = auth.complete_initial_setup(
        "owner",
        "new-secure-password",
        {"workspace_name": "Engineering", "scan_preset": "standard"},
    )

    assert principal.username == "owner"
    assert principal.role == "admin"
    assert auth.authenticate("owner", "new-secure-password") is not None
    assert auth.authenticate("admin", "temporary-password") is None
    assert database.get_application_state("setup_completed") is True
    assert database.get_application_state("workspace_settings")["workspace_name"] == "Engineering"

    auth.ensure_bootstrap_admin()
    assert auth.authenticate("admin", "temporary-password") is None


def test_setup_token_can_create_an_unusable_temporary_bootstrap_identity(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "setup-token.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(auth, "get_connection", database.get_connection)
    monkeypatch.delenv("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("AEGIS_SETUP_TOKEN", "s" * 32)
    database.initialize_database(reset=True)

    auth.ensure_bootstrap_admin()

    with database.get_connection() as connection:
        row = connection.execute(
            "SELECT username, password_hash FROM auth_users WHERE username = 'admin'"
        ).fetchone()
    assert row is not None
    assert auth.verify_password("", row[1]) is False


def test_unauthenticated_development_mode_uses_a_real_database_identity(
    tmp_path, monkeypatch
):
    from app import projects

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "development.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setattr(auth, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "get_connection", database.get_connection)
    monkeypatch.setattr(projects, "USING_POSTGRES", False)
    monkeypatch.setattr(auth, "AUTH_REQUIRED", False)
    database.initialize_database(reset=True)
    auth.ensure_development_admin()

    principal = auth._development_principal()
    assert principal is not None
    assert principal.user_id > 0
    project_id = projects.create_project(
        name="Development project",
        repository_url="",
        github_full_name="",
        default_branch="main",
        scan_preset="quick",
        user_id=principal.user_id,
    )
    assert projects.get_project(project_id)["created_by"] == principal.user_id


def test_unauthenticated_server_bind_is_limited_to_loopback():
    assert validate_server_bind("127.0.0.1", auth_required=False) == "127.0.0.1"
    assert validate_server_bind("::1", auth_required=False) == "::1"

    try:
        validate_server_bind("0.0.0.0", auth_required=False)
    except RuntimeError as exc:
        assert "Refusing to expose Aegis" in str(exc)
    else:
        raise AssertionError("Unauthenticated non-loopback bind must be rejected")

    assert validate_server_bind("0.0.0.0", auth_required=True) == "0.0.0.0"
