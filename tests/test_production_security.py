from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth
from app import database
from app.database import InMemoryRedis
from app.rate_limit import RateLimitMiddleware


def test_password_hashes_are_salted_and_verified():
    first = auth.hash_password("correct horse battery staple")
    second = auth.hash_password("correct horse battery staple")

    assert first != second
    assert auth.verify_password("correct horse battery staple", first)
    assert not auth.verify_password("wrong password", first)


def test_signed_session_rejects_tampering(monkeypatch):
    monkeypatch.setenv("AEGIS_SESSION_SECRET", "s" * 32)
    principal = auth.Principal(7, "operator", "operator", "csrf")
    session = auth.create_session(principal)
    payload, signature = session.split(".", 1)
    tampered = ("A" if payload[0] != "A" else "B") + payload[1:] + "." + signature

    assert auth._decode_session(session) == principal
    assert auth._decode_session(tampered) is None


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
