"""Malformed client input is rejected with 4xx instead of crashing the request (found by API fuzzing)."""
import pytest
from fastapi.testclient import TestClient

import app.main as app_main


@pytest.fixture
def client():
    from app.database import initialize_database

    initialize_database(reset=True)
    return TestClient(app_main.app)


@pytest.mark.parametrize(
    "body",
    [b"[]", b'"text"', b"null", b"{", b"\xff\xfe\x00", b"[" * 5000 + b"]" * 5000],
    ids=["list", "string", "null", "truncated", "bad-encoding", "deep-nesting"],
)
@pytest.mark.parametrize("path", ["/api/projects", "/api/users"])
def test_non_object_json_bodies_are_rejected(client, path, body):
    response = client.post(path, content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["detail"] == "JSON object body required."


def test_login_rejects_non_object_body(client):
    response = client.post("/api/auth/login", json=["admin", "password"])
    assert response.status_code == 400


def test_identifier_wider_than_64_bits_is_rejected(client):
    response = client.get("/api/projects/9223372036854775808/scans")
    assert response.status_code == 400


def test_unhashable_user_role_is_rejected(client):
    response = client.patch("/api/users/1", json={"role": ["admin"]})
    assert response.status_code == 400


def test_github_import_without_connection_is_a_conflict(client, monkeypatch):
    from app.routes import github_routes

    def not_connected(user_id):
        raise ValueError("GitHub is not connected.")

    monkeypatch.setattr(github_routes, "list_repositories", not_connected)
    response = client.post("/api/github/import", json={"full_name": "example/api"})
    assert response.status_code == 409
