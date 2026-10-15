import json
import secrets
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime
from urllib.parse import urlsplit

import pytest
import requests
from fastapi.testclient import TestClient

from app import bac_lab


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "test")
    return {actor: secrets.token_urlsafe(32) for actor in ("alice", "bob", "admin")}


@pytest.fixture
def control_token():
    return secrets.token_urlsafe(32)


@pytest.fixture
def clients(credentials, control_token):
    with ExitStack() as stack:
        def create(mode="fixed"):
            app = bac_lab.create_bac_app(
                mode=mode,
                tokens=credentials,
                control_token=control_token,
                instance_id=secrets.token_hex(16),
            )
            return stack.enter_context(TestClient(app))

        yield create


def auth(credentials, actor):
    return {"Authorization": f"Bearer {credentials[actor]}"}


def research_headers(control_token):
    return {"X-Aegis-Lab-Key": control_token}


def snapshot(client, control_token):
    response = client.get("/_research/snapshot", headers=research_headers(control_token))
    assert response.status_code == 200
    return response.json()


def test_seed_is_reproducible_and_instances_are_isolated(clients, credentials, control_token):
    first, second = clients(), clients("vulnerable")
    first_info = first.get("/_research/info", headers=research_headers(control_token)).json()
    second_info = second.get("/_research/info", headers=research_headers(control_token)).json()
    assert first_info["lab"] == "aegis-bac-v2"
    assert first_info["mode"] == "fixed"
    assert second_info["mode"] == "vulnerable"
    assert first_info["instance_id"] != second_info["instance_id"]
    assert first_info["seed_sha256"] == second_info["seed_sha256"]
    assert len(first_info["seed_sha256"]) == 64
    baseline = snapshot(first, control_token)
    assert set(baseline["documents"]) == {
        "alice-private-1", "bob-private-1", "alice-private-2", "bob-private-2",
        "alice-public", "bob-public",
    }
    assert set(baseline["users"]) == {"alice", "bob", "admin"}
    assert len({document["content"] for document in baseline["documents"].values()}) == 6
    first.patch("/documents/alice-private-1", json={"title": "changed"}, headers=auth(credentials, "alice"))
    assert snapshot(first, control_token) != baseline
    assert snapshot(second, control_token) == baseline
    assert first.post("/_research/reset", headers=research_headers(control_token)).status_code == 200
    assert snapshot(first, control_token) == baseline


@pytest.mark.parametrize("actor,role", [("alice", "user"), ("bob", "user"), ("admin", "admin")])
def test_me_resolves_credentials(clients, credentials, actor, role):
    response = clients().get("/me", headers=auth(credentials, actor))
    assert response.status_code == 200
    assert response.json() == {"actor": actor, "role": role}


@pytest.mark.parametrize("mode", ["fixed", "vulnerable"])
def test_missing_or_invalid_bearer_never_bypasses_authentication(clients, mode):
    client = clients(mode)
    for headers in ({}, {"Authorization": "Bearer invalid"}, {"Authorization": "Basic invalid"}):
        assert client.get("/me", headers=headers).status_code == 401
        assert client.get("/admin/users", headers=headers).status_code == 401
        assert client.patch("/documents/alice-private-1", json={"title": "changed"}, headers=headers).status_code == 401
    assert client.get("/documents/alice-private-1").status_code == 403
    assert client.get("/documents/alice-public", headers={"Authorization": "Bearer invalid"}).status_code == 401


@pytest.mark.parametrize("mode,status", [("fixed", 403), ("vulnerable", 200)])
def test_cross_user_read_depends_on_mode(clients, credentials, control_token, mode, status):
    client = clients(mode)
    response = client.get("/documents/bob-private-1", headers=auth(credentials, "alice"))
    assert response.status_code == status
    if status == 200:
        assert response.json() == snapshot(client, control_token)["documents"]["bob-private-1"]


@pytest.mark.parametrize("mode", ["fixed", "vulnerable"])
@pytest.mark.parametrize("actor", ["alice", "admin", "guest"])
def test_public_reads_are_safe_controls(clients, credentials, mode, actor):
    headers = {} if actor == "guest" else auth(credentials, actor)
    response = clients(mode).get("/documents/bob-public", headers=headers)
    assert response.status_code == 200
    assert response.json()["public"] is True
    assert response.json()["content"]


def test_fixed_preview_200_is_masked_for_nonowners(clients, credentials, control_token):
    client = clients()
    private_document = snapshot(client, control_token)["documents"]["bob-private-1"]
    for headers in ({}, auth(credentials, "alice")):
        response = client.get("/documents/bob-private-1/preview", headers=headers)
        assert response.status_code == 200
        assert set(response.json()) == {"id", "title"}
        assert private_document["content"] not in response.text
    for actor in ("bob", "admin"):
        response = client.get("/documents/bob-private-1/preview", headers=auth(credentials, actor))
        assert response.json()["content"] == private_document["content"]


def test_vulnerable_preview_exposes_content_only_to_authenticated_actors(clients, credentials):
    client = clients("vulnerable")
    assert "content" in client.get("/documents/bob-private-1/preview", headers=auth(credentials, "alice")).json()
    assert "content" not in client.get("/documents/bob-private-1/preview").json()


@pytest.mark.parametrize("mode,status", [("fixed", 403), ("vulnerable", 200)])
@pytest.mark.parametrize("operation", ["patch", "delete"])
def test_cross_user_mutations_are_confirmed_by_state(clients, credentials, control_token, mode, status, operation):
    client = clients(mode)
    original = snapshot(client, control_token)["documents"]["bob-private-2"]
    arguments = {"headers": auth(credentials, "alice")}
    if operation == "patch":
        arguments["json"] = {"title": "Research mutation"}
    response = getattr(client, operation)("/documents/bob-private-2", **arguments)
    assert response.status_code == status
    after = snapshot(client, control_token)["documents"]
    if status == 403:
        assert after["bob-private-2"] == original
    elif operation == "delete":
        assert "bob-private-2" not in after
    else:
        assert after["bob-private-2"] == {**original, "title": "Research mutation"}


@pytest.mark.parametrize("actor", ["alice", "admin"])
def test_fixed_owners_and_admins_may_mutate(clients, credentials, actor):
    client = clients()
    assert client.patch("/documents/alice-private-1", json={"title": "Own edit"}, headers=auth(credentials, actor)).status_code == 200
    assert client.delete("/documents/alice-private-1", headers=auth(credentials, actor)).status_code == 200
    assert client.get("/documents/alice-private-1", headers=auth(credentials, actor)).status_code == 404


@pytest.mark.parametrize("mode,status", [("fixed", 403), ("vulnerable", 200)])
def test_admin_role_bypass_and_disable_have_real_effects(clients, credentials, control_token, mode, status):
    client = clients(mode)
    response = client.get("/admin/users", headers=auth(credentials, "alice"))
    assert response.status_code == status
    if status == 200:
        assert response.json()["private_marker"] == "synthetic-admin-marker"
        assert {user["id"] for user in response.json()["users"]} == {"alice", "bob", "admin"}
    response = client.post("/admin/users/bob/disable", headers=auth(credentials, "alice"))
    assert response.status_code == status
    assert snapshot(client, control_token)["users"]["bob"]["active"] is (status == 403)
    if status == 200:
        assert client.get("/me", headers=auth(credentials, "bob")).status_code == 401
    assert client.get("/admin/users", headers=auth(credentials, "admin")).status_code == 200


def test_admin_disable_and_reset_restore_authentication(clients, credentials, control_token):
    client = clients()
    assert client.post("/admin/users/alice/disable", headers=auth(credentials, "admin")).status_code == 200
    assert client.get("/me", headers=auth(credentials, "alice")).status_code == 401
    client.post("/_research/reset", headers=research_headers(control_token))
    assert client.get("/me", headers=auth(credentials, "alice")).status_code == 200


@pytest.mark.parametrize("payload", [{}, {"title": ""}, {"title": " "}, {"title": "x" * 201}, {"title": 123}, {"title": "ok", "owner": "alice"}])
def test_invalid_mutation_payloads_are_rejected(clients, credentials, control_token, payload):
    client = clients()
    baseline = snapshot(client, control_token)
    response = client.patch("/documents/alice-private-1", json=payload, headers=auth(credentials, "alice"))
    assert response.status_code == 422
    assert snapshot(client, control_token) == baseline


def test_unknown_and_invalid_identifiers_are_bounded(clients, credentials, control_token):
    client = clients()
    for path in ("/documents/not-present", "/documents/not-present/preview"):
        assert client.get(path, headers=auth(credentials, "admin")).status_code == 404
    assert client.patch("/documents/not-present", json={"title": "ok"}, headers=auth(credentials, "admin")).status_code == 404
    assert client.delete("/documents/not-present", headers=auth(credentials, "admin")).status_code == 404
    assert client.post("/admin/users/not-present/disable", headers=auth(credentials, "admin")).status_code == 404
    assert client.get("/documents/" + "x" * 65).status_code == 422
    assert client.get("/documents/bad%20id").status_code == 422
    assert client.get("/_research/events", params={"case_id": "x" * 129}, headers=research_headers(control_token)).status_code == 422


@pytest.mark.parametrize("path,method", [("info", "get"), ("snapshot", "get"), ("events", "get"), ("reset", "post")])
def test_control_routes_require_separate_key(clients, credentials, control_token, path, method):
    client = clients()
    for headers in ({}, auth(credentials, "admin"), {"X-Aegis-Lab-Key": credentials["admin"]}):
        assert getattr(client, method)(f"/_research/{path}", headers=headers).status_code == 401
    assert getattr(client, method)(f"/_research/{path}", headers=research_headers(control_token)).status_code == 200


def test_audit_is_correlated_secret_free_and_survives_reset(clients, credentials, control_token):
    client = clients()
    for request_id, path in (("request-1", "/me"), ("request-2", "/documents/bob-private-1")):
        headers = {**auth(credentials, "alice"), "X-Aegis-Case-ID": "case-1", "X-Aegis-Request-ID": request_id}
        client.get(path, headers=headers)
    client.get("/me", headers={**auth(credentials, "admin"), "X-Aegis-Case-ID": "case-2"})
    client.post("/_research/reset", headers=research_headers(control_token))
    response = client.get("/_research/events", params={"case_id": "case-1"}, headers=research_headers(control_token))
    events = response.json()["events"]
    assert len(events) == 2
    assert [event["status_code"] for event in events] == [200, 403]
    assert [event["request_id"] for event in events] == ["request-1", "request-2"]
    assert all(event["actor"] == "alice" and event["method"] == "GET" and event["case_id"] == "case-1" for event in events)
    assert all(datetime.fromisoformat(event["timestamp"]).tzinfo is not None for event in events)
    all_events = client.get("/_research/events", headers=research_headers(control_token)).json()["events"]
    assert len(all_events) == 3
    serialized = json.dumps(all_events)
    assert all(token not in serialized for token in (*credentials.values(), control_token))
    assert "Authorization" not in serialized
    assert all(not event["path"].startswith("/_research") for event in all_events)


@pytest.mark.parametrize("name", ["X-Aegis-Request-ID", "X-Aegis-Case-ID"])
@pytest.mark.parametrize("value", ["x" * 129, "unsafe value", "<unsafe>"])
def test_correlation_headers_reject_unsafe_values(clients, credentials, control_token, name, value):
    client = clients()
    response = client.get("/me", headers={**auth(credentials, "alice"), name: value})
    assert response.status_code == 400
    events = client.get("/_research/events", headers=research_headers(control_token)).json()["events"]
    assert value not in json.dumps(events)


def test_event_storage_is_bounded(clients, credentials, control_token, monkeypatch):
    assert bac_lab._MAX_EVENTS == 4096
    monkeypatch.setattr(bac_lab, "_MAX_EVENTS", 3)
    client = clients()
    for index in range(5):
        client.get("/me", headers={**auth(credentials, "alice"), "X-Aegis-Request-ID": f"request-{index}"})
    events = client.get("/_research/events", headers=research_headers(control_token)).json()["events"]
    assert [event["request_id"] for event in events] == ["request-2", "request-3", "request-4"]


def test_concurrent_deletes_are_atomic(clients, credentials):
    client = clients()
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda _: client.delete("/documents/alice-private-1", headers=auth(credentials, "alice")), range(16)))
    assert sorted(response.status_code for response in responses) == [200] + [404] * 15


def test_invalid_factory_settings_fail_closed(credentials, control_token, monkeypatch):
    settings = {"mode": "fixed", "tokens": credentials, "control_token": control_token, "instance_id": "test-instance"}
    for overrides in (
        {"mode": "production"},
        {"tokens": {**credentials, "bob": credentials["alice"]}},
        {"tokens": {"alice": credentials["alice"]}},
        {"tokens": {**credentials, "guest": "guest-token"}},
        {"control_token": credentials["alice"]},
        {"control_token": ""},
        {"tokens": {**credentials, "alice": "unsafe token"}},
        {"instance_id": "unsafe instance"},
    ):
        with pytest.raises(ValueError):
            bac_lab.create_bac_app(**{**settings, **overrides})
    monkeypatch.setenv("AEGIS_ENV", " Production ")
    with pytest.raises(ValueError, match="production"):
        bac_lab.create_bac_app(**settings)
    with pytest.raises(ValueError, match="production"):
        with bac_lab.local_bac_lab("fixed"):
            pytest.fail("production must never start the lab")


def assert_port_closed(base_url):
    address = urlsplit(base_url)
    with pytest.raises(OSError):
        with socket.create_connection((address.hostname, address.port), timeout=0.3):
            pytest.fail("BAC server must be stopped")


def test_real_http_runtime_is_loopback_and_cleans_up(credentials):
    with requests.Session() as session:
        session.trust_env = False
        with bac_lab.local_bac_lab("fixed") as lab:
            assert urlsplit(lab.base_url).hostname == "127.0.0.1"
            assert lab.mode == "fixed"
            assert set(lab.tokens) == {"alice", "bob", "admin"}
            assert len(set((*lab.tokens.values(), lab.control_token))) == 4
            response = session.get(lab.base_url + "/_research/info", headers=research_headers(lab.control_token), timeout=2, allow_redirects=False)
            assert response.status_code == 200
            assert response.json()["instance_id"] == lab.instance_id
            response = session.get(lab.base_url + "/documents/bob-private-1", headers=auth(lab.tokens, "alice"), timeout=2, allow_redirects=False)
            assert response.status_code == 403
            with pytest.raises(TypeError):
                lab.tokens["alice"] = "changed"
        assert_port_closed(lab.base_url)


def test_runtime_cleans_up_when_body_raises(credentials):
    with pytest.raises(RuntimeError, match="test body failure"):
        with bac_lab.local_bac_lab("vulnerable") as lab:
            raise RuntimeError("test body failure")
    assert_port_closed(lab.base_url)


def test_runtime_surfaces_startup_failures(credentials, monkeypatch):
    listener = None

    def broken_run(*args, **kwargs):
        nonlocal listener
        listener = kwargs["sockets"][0]
        raise RuntimeError("test startup failure")

    monkeypatch.setattr(bac_lab.uvicorn.Server, "run", broken_run)
    with pytest.raises(RuntimeError, match="start"):
        with bac_lab.local_bac_lab("fixed"):
            pytest.fail("a failed server must not yield a running lab")
    assert listener.fileno() == -1


def test_runtime_startup_timeout_stops_thread_and_closes_socket(credentials, monkeypatch):
    listener = None

    def slow_start(server, *, sockets):
        nonlocal listener
        listener = sockets[0]
        while not server.should_exit:
            threading.Event().wait(0.005)

    monkeypatch.setattr(bac_lab, "_START_SECONDS", 0.03)
    monkeypatch.setattr(bac_lab.uvicorn.Server, "run", slow_start)
    with pytest.raises(RuntimeError, match="startup timed out"):
        with bac_lab.local_bac_lab("fixed"):
            pytest.fail("an unready server must not be yielded")
    assert listener.fileno() == -1
    assert not any(thread.name.startswith("aegis-bac-") for thread in threading.enumerate())


def test_runtime_force_exit_fallback_remains_bounded(credentials, monkeypatch):
    def slow_stop(server, *, sockets):
        server.started = True
        while not server.force_exit:
            threading.Event().wait(0.005)

    monkeypatch.setattr(bac_lab, "_STOP_SECONDS", 0.03)
    monkeypatch.setattr(bac_lab.uvicorn.Server, "run", slow_stop)
    with bac_lab.local_bac_lab("fixed") as lab:
        assert lab.base_url.startswith("http://127.0.0.1:")
    assert_port_closed(lab.base_url)
    assert not any(thread.name.startswith("aegis-bac-") for thread in threading.enumerate())


def test_import_does_not_load_production_application_or_database():
    result = subprocess.run(
        [sys.executable, "-c", "import app.bac_lab, sys; assert not {'app.main', 'app.database', 'app.demo_lab'} & set(sys.modules)"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mode, leaked", [("fixed", False), ("vulnerable", True)])
def test_export_denial_leaks_only_in_vulnerable_error_body(clients, credentials, mode, leaked):
    client = clients(mode)
    own = client.get("/documents/alice-private-2/export", headers=auth(credentials, "alice"))
    denied = client.get("/documents/alice-private-2/export", headers=auth(credentials, "bob"))
    guest = client.get("/documents/alice-private-2/export")
    assert own.status_code == 200 and own.json()["content"].startswith("synthetic-canary:")
    assert denied.status_code == guest.status_code == 403
    assert ("document" in denied.json()) is leaked
    assert "document" not in guest.json()


@pytest.mark.parametrize("mode, written", [("fixed", False), ("vulnerable", True)])
def test_rename_denial_writes_only_in_vulnerable_mode(clients, credentials, control_token, mode, written):
    client = clients(mode)
    response = client.put("/documents/alice-private-2/title", json={"title": "marker"}, headers=auth(credentials, "bob"))
    assert response.status_code == 403
    assert (snapshot(client, control_token)["documents"]["alice-private-2"]["title"] == "marker") is written
    assert client.put("/documents/alice-private-2/title", json={"title": "own"}, headers=auth(credentials, "alice")).json()["title"] == "own"


@pytest.mark.parametrize("mode, visible", [("fixed", False), ("vulnerable", True)])
def test_list_filters_other_users_documents_only_when_fixed(clients, credentials, mode, visible):
    client = clients(mode)
    listed = {item["id"] for item in client.get("/documents", headers=auth(credentials, "bob")).json()["documents"]}
    guest = {item["id"] for item in client.get("/documents").json()["documents"]}
    assert {"bob-private-1", "bob-private-2", "alice-public", "bob-public"} <= listed
    assert ("alice-private-2" in listed) is visible
    assert guest == {"alice-public", "bob-public"}
