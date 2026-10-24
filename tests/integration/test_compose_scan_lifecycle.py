"""Opt-in production-stack scan lifecycle coverage.

The regular suite intentionally replaces Redis/RQ and uses SQLite for speed.
This module is enabled only by the Compose CI job so it can exercise the real
dashboard, Redis queue/event path, worker, PostgreSQL metadata, and artifact
API together. Once enabled, missing prerequisites fail instead of skipping.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest


pytestmark = pytest.mark.integration


def _base_url() -> str:
    if os.environ.get("AEGIS_COMPOSE_INTEGRATION", "").lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }:
        pytest.skip("Compose integration tests are disabled.")
    return os.environ.get("AEGIS_INTEGRATION_BASE_URL", "http://127.0.0.1:5001").rstrip("/")


def _admin_token(client: httpx.Client) -> str:
    """Use a supplied token, or mint a short-lived one as the bootstrap admin."""
    token = os.environ.get("AEGIS_INTEGRATION_ADMIN_TOKEN", "")
    if token:
        return token
    password = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not password:
        pytest.fail(
            "Compose integration is enabled, but neither AEGIS_INTEGRATION_ADMIN_TOKEN "
            "nor AEGIS_BOOTSTRAP_ADMIN_PASSWORD is set."
        )
    username = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_USERNAME", "admin")
    login = client.post("/api/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200, login.text
    # The production session cookie is Secure, so send it explicitly over plain HTTP.
    session = {
        "Cookie": f"aegis_session={login.cookies['aegis_session']}",
        "X-CSRF-Token": login.json()["csrf_token"],
    }
    users = client.get("/api/users", headers=session)
    assert users.status_code == 200, users.text
    user_id = next(user["id"] for user in users.json()["users"] if user["username"] == username)
    minted = client.post(
        f"/api/users/{user_id}/tokens",
        headers=session,
        json={
            "name": "compose-integration",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )
    assert minted.status_code == 201, minted.text
    return minted.json()["token"]


def _wait_for_ready(client: httpx.Client) -> None:
    last_status = "unknown"
    for _ in range(60):
        response = client.get("/ready")
        last_status = f"{response.status_code}: {response.text[:300]}"
        if response.is_success:
            return
        time.sleep(1)
    pytest.fail(f"Compose stack did not become ready: {last_status}")


def _collect_websocket_events(base_url: str, token: str, job_id: str) -> list[dict]:
    from websockets.sync.client import connect

    websocket_url = base_url.replace("http://", "ws://", 1).replace(
        "https://", "wss://", 1
    )
    events: list[dict] = []
    deadline = time.monotonic() + 90
    with connect(
        f"{websocket_url}/ws/scan/{job_id}",
        additional_headers={"Authorization": f"Bearer {token}"},
        proxy=None,
        open_timeout=15,
    ) as socket:
        while time.monotonic() < deadline:
            try:
                message = socket.recv(timeout=min(5, max(0.1, deadline - time.monotonic())))
            except TimeoutError:
                continue
            except Exception as exc:  # websockets raises version-specific close types
                if events:
                    break
                raise AssertionError(f"Scan WebSocket closed before sending events: {exc}") from exc
            event = json.loads(message)
            if isinstance(event, dict):
                events.append(event)
                if event.get("type") == "state" and event.get("state") in {
                    "completed",
                    "failed",
                    "cancelled",
                }:
                    break
    return events


def _wait_for_scan(
    client: httpx.Client, project_id: int, scan_run_id: int
) -> dict:
    last_run: dict = {}
    for _ in range(90):
        response = client.get(f"/api/projects/{project_id}/scans/{scan_run_id}")
        assert response.status_code == 200, response.text
        last_run = response.json()
        if last_run.get("state") in {"completed", "failed", "cancelled"}:
            break
        time.sleep(1)
    assert last_run.get("state") == "completed", last_run
    return last_run


def test_compose_scan_reaches_postgres_artifacts_and_websocket_events() -> None:
    base_url = _base_url()
    project_id: int | None = None
    with httpx.Client(base_url=base_url, timeout=20) as client:
        _wait_for_ready(client)
        token = _admin_token(client)
        client.headers["X-Aegis-Token"] = token
        created = client.post(
            "/api/projects",
            json={
                "name": f"Compose lifecycle {uuid4().hex[:10]}",
                "repository_url": "https://github.com/huslenine999/aegis.git",
                "default_branch": "main",
                "scan_preset": "quick",
            },
        )
        assert created.status_code == 201, created.text
        project_id = int(created.json()["id"])
        try:
            started = client.post(
                f"/api/projects/{project_id}/scans",
                json={"preset": "quick"},
            )
            assert started.status_code == 202, started.text
            start_payload = started.json()
            job_id = str(start_payload["job_id"])
            scan_run_id = int(start_payload["scan_run_id"])

            events = _collect_websocket_events(base_url, token, job_id)
            event_types = {event.get("type") for event in events}
            assert "state" in event_types
            assert "log" in event_types
            assert any(
                event.get("type") == "state"
                and event.get("state") == "completed"
                for event in events
            )

            run = _wait_for_scan(client, project_id, scan_run_id)
            assert run["job_id"] == job_id
            assert run["result"]["artifact_base"].endswith(
                f"/api/projects/{project_id}/scans/{scan_run_id}/artifacts"
            )

            artifacts_response = client.get(
                f"/api/projects/{project_id}/scans/{scan_run_id}/artifacts"
            )
            assert artifacts_response.status_code == 200, artifacts_response.text
            artifacts = artifacts_response.json()["artifacts"]
            report = next(item for item in artifacts if item["name"] == "report.html")
            assert report["integrity"] == "verified"

            report_response = client.get(
                f"/api/projects/{project_id}/scans/{scan_run_id}/artifacts/report.html"
            )
            assert report_response.status_code == 200
            assert "Aegis" in report_response.text
        finally:
            if project_id is not None:
                deleted = client.delete(f"/api/projects/{project_id}")
                assert deleted.status_code in {200, 404}, deleted.text
