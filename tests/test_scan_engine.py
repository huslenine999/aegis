from dataclasses import FrozenInstanceError

import pytest

from app.scan_engine import (
    CliEventSink,
    RedisEventSink,
    ScanEvent,
    ScanJobPayload,
    ScanRunner,
)


def test_scan_job_payload_is_typed_and_immutable():
    payload = ScanJobPayload(
        job_id="job-1",
        target="project",
        custom_file_path=None,
        waf_enabled=False,
        scan_run_id=7,
        project_id=11,
        requested_by=13,
        preset="standard",
        source_revision="a" * 40,
        github_installation_id=None,
    )

    assert payload.job_id == "job-1"
    assert payload.as_rq_kwargs() == {
        "job_id": "job-1",
        "target": "project",
        "custom_file_path": None,
        "waf_enabled": False,
        "scan_run_id": 7,
        "project_id": 11,
        "requested_by": 13,
        "preset": "standard",
        "source_revision": "a" * 40,
        "github_installation_id": None,
    }
    with pytest.raises(FrozenInstanceError):
        payload.job_id = "other"


def test_scan_runner_emits_lifecycle_and_tracks_tools():
    events = []
    runner = ScanRunner(CliEventSink(events.append))

    runner.transition("running", 10)
    runner.log("claimed")
    runner.mark_tool("Ruff", "completed", return_code=0)

    assert events == [
        ScanEvent("state", {"state": "running", "progress": 10}),
        ScanEvent("log", {"text": "claimed", "level": "info"}),
        ScanEvent("tool", {"name": "Ruff", "status": "completed", "return_code": 0}),
    ]
    assert runner.tool_statuses.states() == {"Ruff": "completed"}


def test_redis_event_sink_delegates_to_job_event_publisher(monkeypatch):
    published = []
    monkeypatch.setattr(
        "app.scan_engine.publish_job_event",
        lambda job_id, event_type, data: published.append((job_id, event_type, data)),
    )
    sink = RedisEventSink("job-2")

    sink.emit(ScanEvent("state", {"state": "completed", "progress": 100}))

    assert published == [("job-2", "state", {"state": "completed", "progress": 100})]
