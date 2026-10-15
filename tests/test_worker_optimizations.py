"""Worker optimizations preserve lifecycle and retention behavior."""

import json
import os
import time

import pytest

from app import database, projects, worker
from app.scan_engine import ScanJobPayload
from tests.test_projects import configure_project_database


class RecordingRedis(database.InMemoryRedis):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.messages = []
        self.trips = 0
        self.buffered = False

    def _record(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        if not self.buffered:
            self.trips += 1

    def hset(self, *args, **kwargs):
        self._record("hset", *args, **kwargs)
        return super().hset(*args, **kwargs)

    def rpush(self, *args, **kwargs):
        self._record("rpush", *args, **kwargs)
        return super().rpush(*args, **kwargs)

    def ltrim(self, *args, **kwargs):
        self._record("ltrim", *args, **kwargs)
        return super().ltrim(*args, **kwargs)

    def publish(self, *args, **kwargs):
        self._record("publish", *args, **kwargs)
        self.messages.append(args)
        return super().publish(*args, **kwargs)

    def expire(self, *args, **kwargs):
        self._record("expire", *args, **kwargs)
        return super().expire(*args, **kwargs)


class PipelinedRedis(RecordingRedis):
    def pipeline(self):
        owner = self

        class Pipeline:
            def __init__(self):
                self.commands = []

            def __getattr__(self, name):
                def enqueue(*args, **kwargs):
                    self.commands.append((name, args, kwargs))
                    return self
                return enqueue

            def execute(self):
                owner.trips += 1
                owner.buffered = True
                try:
                    return [getattr(owner, name)(*args, **kwargs) for name, args, kwargs in self.commands]
                finally:
                    owner.buffered = False

        return Pipeline()


@pytest.mark.parametrize("client_type", [RecordingRedis, PipelinedRedis])
def test_job_events_preserve_order_history_state_and_expiry(monkeypatch, client_type):
    client = client_type()
    monkeypatch.setattr(worker, "redis_client", client)
    monkeypatch.setattr(worker, "JOB_LOG_LIMIT", 2)
    for text in ("first", "second", "third"):
        worker.publish_job_event("job-1", "log", {"text": text})
    worker.publish_job_event("job-1", "result", {"result": {"is_blocked": False}})
    worker.publish_job_event("job-1", "state", {"state": "completed", "progress": 100})

    assert [json.loads(item)["text"] for item in client.lrange("job_logs:job-1", 0, -1)] == ["second", "third"]
    assert client.hget("job:job-1", "state") == b"completed"
    assert client.hget("job:job-1", "progress") == b"100"
    assert json.loads(client.hget("job:job-1", "result")) == {"is_blocked": False}
    assert [json.loads(message)["type"] for _, message in client.messages] == ["log", "log", "log", "result", "state"]
    assert [call[0] for call in client.calls[:9]] == ["rpush", "ltrim", "publish"] * 3
    assert client.calls[-2:] == [
        ("expire", ("job:job-1", worker.JOB_RETENTION_SECONDS), {}),
        ("expire", ("job_logs:job-1", worker.JOB_RETENTION_SECONDS), {}),
    ]
    if client_type is PipelinedRedis:
        assert client.trips == 5


def test_cleanup_skips_fresh_runs_and_retains_active_expired_runs(tmp_path, monkeypatch):
    runs = tmp_path / "tenants/7/projects/11/runs"
    runs.mkdir(parents=True)
    now = time.time()
    states = {"fresh": b"completed", "active": b"analyzing", "terminal": b"completed", "current": b"completed", "expired-state": None}
    for name in states:
        directory = runs / name
        directory.mkdir()
        if name != "fresh":
            expired = now - (worker.ARTIFACT_RETENTION_DAYS + 1) * 86400
            os.utime(directory, (expired, expired))
    lookups = []

    class Redis:
        def hget(self, key, field):
            lookups.append((key, field))
            return states[key.removeprefix("job:")]

    monkeypatch.setattr(worker, "SCANS_DIR", tmp_path)
    monkeypatch.setattr(worker, "redis_client", Redis())
    worker._cleanup_expired_artifacts("current")

    assert {key for key, _ in lookups} == {"job:active", "job:terminal", "job:expired-state"}
    assert {path.name for path in runs.iterdir()} == {"fresh", "active", "current"}


def test_worker_completes_synthetic_upload_without_visual_sleep(tmp_path, monkeypatch):
    source = tmp_path / "plain.txt"
    source.write_text("A harmless synthetic document.\n")
    client = database.InMemoryRedis()
    monkeypatch.setattr(worker, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(worker, "redis_client", client)
    monkeypatch.setattr(worker, "_source_revision", lambda _: "unavailable")
    monkeypatch.setenv("AEGIS_ENABLE_YARA", "false")

    def unexpected_sleep(_):
        pytest.fail("The worker held a completed scan for a visual transition")

    monkeypatch.setattr(worker.time, "sleep", unexpected_sleep)
    worker.async_scan_task(ScanJobPayload("quick-upload", "upload", custom_file_path=str(source)))

    assert client.hget("job:quick-upload", "state") == b"completed"
    assert (tmp_path / "scans/runs/quick-upload/scan-manifest.json").is_file()
    assert source.read_text() == "A harmless synthetic document.\n"


def test_worker_finding_counts_match_database_events_and_notifications(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    source = tmp_path / "plain.txt"
    source.write_text("Synthetic project evidence.\n")
    project_id = projects.create_project(
        name="Synthetic counts", repository_url="", github_full_name="", default_branch="main",
        scan_preset="quick", user_id=10,
    )
    run_id = projects.create_scan_run(
        job_id="finding-counts", project_id=project_id, requested_by=10, target="project", preset="quick",
    )
    client = database.InMemoryRedis()
    notifications = []
    check_summaries = []
    monkeypatch.setattr(worker, "SCANS_DIR", tmp_path / "scans")
    monkeypatch.setattr(worker, "redis_client", client)
    monkeypatch.setattr(worker, "_source_revision", lambda _: "unavailable")
    monkeypatch.setattr(worker, "sync_findings", lambda *args: {"created": 2, "reopened": 1})
    monkeypatch.setattr(worker, "queue_project_notification", lambda project, event, payload: notifications.append(payload))
    monkeypatch.setattr(worker, "_complete_github_scan_check", lambda run, project, conclusion, summary, *args: check_summaries.append(summary))
    monkeypatch.setenv("AEGIS_ENABLE_YARA", "false")
    worker.async_scan_task(ScanJobPayload(
        "finding-counts", "project", custom_file_path=str(source), scan_run_id=run_id,
        project_id=project_id, requested_by=10, preset="quick",
    ))

    stored = projects.get_scan_run(run_id)
    result = json.loads(client.hget("job:finding-counts", "result"))
    assert stored["new_findings"] == stored["result"]["new_findings"] == result["new_findings"] == 3
    assert notifications[0]["new_findings"] == 3
    assert "New findings: 3." in check_summaries[0]


def test_dead_worker_marks_unfinished_scan_failed_once(tmp_path, monkeypatch):
    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="Killed worker", repository_url="", github_full_name="", default_branch="main",
        scan_preset="quick", user_id=10,
    )
    running = projects.create_scan_run(
        job_id="killed", project_id=project_id, requested_by=10, target="project", preset="quick",
    )
    finished = projects.create_scan_run(
        job_id="finished", project_id=project_id, requested_by=10, target="project", preset="quick",
    )
    projects.update_scan_run(running, state="running", progress=10)
    projects.update_scan_run(finished, state="completed", progress=100)
    checks = []
    monkeypatch.setattr(worker, "_complete_github_scan_check", lambda run, project, conclusion, summary: checks.append((run, conclusion)))

    for run_id in (running, finished):
        job = type("Job", (), {"args": (ScanJobPayload(str(run_id), "project", scan_run_id=run_id, project_id=project_id),)})()
        worker.mark_scan_failed(job, None, RuntimeError, RuntimeError(), None)

    assert projects.get_scan_run(running)["state"] == "failed"
    assert projects.get_scan_run(finished)["state"] == "completed"
    assert checks == [(running, "failure")]


def test_queue_failure_fails_scan_instead_of_leaving_it_queued(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import fastapi
    from app.routes import project_routes

    configure_project_database(tmp_path, monkeypatch)
    project_id = projects.create_project(
        name="Queue down", repository_url="", github_full_name="", default_branch="main",
        scan_preset="quick", user_id=10,
    )

    class BrokenRedis(database.InMemoryRedis):
        def hset(self, *args, **kwargs):
            raise ConnectionError("redis unavailable")

    monkeypatch.setattr(project_routes, "redis_client", BrokenRedis())
    monkeypatch.setattr(worker, "_complete_github_scan_check", lambda *args: None)
    with pytest.raises(fastapi.HTTPException) as error:
        project_routes._enqueue_project_scan(
            projects.get_project(project_id), SimpleNamespace(user_id=10), "quick"
        )

    assert error.value.status_code == 503
    [run] = projects.list_scan_runs(project_id)
    assert run["state"] == "failed"
