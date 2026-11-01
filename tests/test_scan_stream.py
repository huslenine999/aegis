"""The live scan log stream must end and must never block the event loop."""

import asyncio
import json
from types import SimpleNamespace

from app import database, worker
from app.routes import scan_routes
from app.scan_engine import ScanJobPayload


class FakeWebSocket:
    client = SimpleNamespace(host="127.0.0.1")

    def __init__(self):
        self.sent = []

    async def accept(self):
        pass

    async def close(self, code=1000, reason=""):
        self.sent.append({"closed": code})

    async def send_json(self, data):
        self.sent.append(data)


def _stream_setup(monkeypatch, state=None):
    client = database.InMemoryRedis()
    client.hset("job:job-1", "owner_id", 5)
    if state:
        client.hset("job:job-1", mapping={"state": state, "progress": 40})
    monkeypatch.setattr(scan_routes, "redis_client", client)
    monkeypatch.setattr(scan_routes, "websocket_principal", lambda *args: SimpleNamespace(user_id=5))
    monkeypatch.setattr(scan_routes, "allow_websocket", lambda *args: True)
    monkeypatch.setattr(scan_routes, "POLL_SECONDS", 0.01)
    return client


def _run(coroutine, seconds=5):
    return asyncio.run(asyncio.wait_for(coroutine, seconds))


def test_stream_of_a_finished_job_ends_at_once(monkeypatch):
    _stream_setup(monkeypatch, state="completed")
    socket = FakeWebSocket()
    _run(scan_routes.websocket_scan(socket, "job-1"), seconds=1)
    assert socket.sent[-1]["state"] == "completed"


def test_stream_ends_when_the_final_state_is_stored_but_never_published(monkeypatch):
    client = _stream_setup(monkeypatch, state="running")
    monkeypatch.setattr(scan_routes, "STATE_CHECK_SECONDS", 0.05)

    async def scenario():
        socket = FakeWebSocket()
        stream = asyncio.create_task(scan_routes.websocket_scan(socket, "job-1"))
        await asyncio.sleep(0.1)
        client.hset("job:job-1", "state", "failed")  # e.g. a killed worker
        await stream
        return socket

    socket = _run(scenario())
    assert socket.sent[-1] == {"type": "state", "state": "failed", "progress": 100}


def test_stream_ends_at_its_deadline(monkeypatch):
    _stream_setup(monkeypatch, state="running")
    monkeypatch.setattr(scan_routes, "SCAN_JOB_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(scan_routes, "STREAM_GRACE_SECONDS", 0.1)
    _run(scan_routes.websocket_scan(FakeWebSocket(), "job-1"))


def test_stream_does_not_block_the_event_loop(monkeypatch):
    client = _stream_setup(monkeypatch, state="running")
    calls = []

    def recording_pubsub():
        pubsub = database.InMemoryRedis.pubsub(client)
        real = pubsub.get_message

        def get_message(**kwargs):
            calls.append(kwargs.get("timeout"))
            return real(**kwargs)

        pubsub.get_message = get_message
        return pubsub

    client.pubsub = recording_pubsub

    async def scenario():
        stream = asyncio.create_task(scan_routes.websocket_scan(FakeWebSocket(), "job-1"))
        await asyncio.sleep(0.05)
        client.publish("job_channel:job-1", json.dumps({"type": "state", "state": "completed"}))
        await stream

    _run(scenario())
    assert calls and set(calls) == {0}


def test_dead_worker_publishes_the_failed_state(tmp_path, monkeypatch):
    from app import projects

    from tests.test_projects import configure_project_database

    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="Killed", repository_url="", github_full_name="", default_branch="main",
        scan_preset="quick", user_id=10,
    )
    run_id = projects.create_scan_run(
        job_id="killed", project_id=project_id, requested_by=10, target="project", preset="quick",
    )
    projects.update_scan_run(run_id, state="running", progress=10)
    client = database.InMemoryRedis()
    monkeypatch.setattr(worker, "redis_client", client)
    monkeypatch.setattr(worker, "_complete_github_scan_check", lambda *args: None)
    pubsub = client.pubsub()
    pubsub.subscribe("job_channel:killed")

    job = SimpleNamespace(args=(ScanJobPayload("killed", "project", scan_run_id=run_id, project_id=project_id),))
    worker.mark_scan_failed(job)
    worker.mark_scan_failed(job)  # A second call finds the run final and publishes nothing.

    messages = []
    while (message := pubsub.get_message()) is not None:
        messages.append(json.loads(message["data"]))
    assert messages == [{"type": "state", "state": "failed", "progress": 100}]
    assert client.hget("job:killed", "state") == b"failed"
