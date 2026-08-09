"""Opt-in production-stack scan lifecycle coverage.

The regular suite intentionally replaces Redis/RQ and uses SQLite for speed.
This module is enabled only by the Compose CI job so it can exercise the real
dashboard, Redis queue/event path, worker, PostgreSQL metadata, and artifact
API together.
"""

from __future__ import annotations

import json
import os
import time
from uuid import uuid4

import httpx
import pytest


pytestmark = pytest.mark.integration


def _configuration() -> tuple[str, str]:
    if os.environ.get("AEGIS_COMPOSE_INTEGRATION", "").lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }:
        pytest.skip("Compose integration tests are disabled.")
    base_url = os.environ.get("AEGIS_INTEGRATION_BASE_URL", "http://127.0.0.1:5001")
    token = os.environ.get("AEGIS_INTEGRATION_ADMIN_TOKEN", os.environ.get("AEGIS_ADMIN_TOKEN", ""))
    if not token:
        pytest.skip("AEGIS integration admin token is not configured.")
    return base_url.rstrip("/"), token


def _headers(token: str) -> dict[str, str]:
    return {"X-Aegis-Token": token}


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
    base_url, token = _configuration()
    headers = _headers(token)
    project_id: int | None = None
    with httpx.Client(base_url=base_url, headers=headers, timeout=20) as client:
        _wait_for_ready(client)
        created = client.post(
            "/api/projects",
            json={
                "name": f"Compose lifecycle {uuid4().hex[:10]}",
                "repository_url": "",
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
