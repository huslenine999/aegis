import json
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from app.scan_engine import (
    CliEventSink,
    RedisEventSink,
    ScanEvent,
    ScanJobPayload,
    ScanRunner,
    build_ruff_command,
)


def test_scan_job_payload_is_typed_and_immutable():
    payload = ScanJobPayload(
        job_id="job-1",
        target="project",
        custom_file_path=None,
        scan_run_id=7,
        project_id=11,
        requested_by=13,
        preset="standard",
        source_revision="a" * 40,
        github_installation_id=None,
        diff_aware=False,
    )

    assert payload.job_id == "job-1"
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


def test_ruff_command_ignores_target_policy_and_inline_suppressions():
    command = build_ruff_command(
        "/usr/bin/python3",
        "/tmp/target",
        {".git", "node_modules"},
    )

    assert command[:4] == ["/usr/bin/python3", "-m", "ruff", "check"]
    assert "--isolated" in command
    assert "--ignore-noqa" in command
    assert "--no-respect-gitignore" in command
    assert command[command.index("--exclude") + 1] == ".git,node_modules"


def test_ruff_scans_files_the_target_lists_in_its_ignore_files(tmp_path):
    (tmp_path / "sub").mkdir()
    for path in (tmp_path / "hidden.py", tmp_path / "sub" / "also_hidden.py"):
        path.write_text("def run(value):\n    return eval(value)\n")
    (tmp_path / ".gitignore").write_text("hidden.py\n")
    (tmp_path / "sub" / ".ignore").write_text("also_hidden.py\n")
    (tmp_path / ".git").mkdir()  # .gitignore applies inside a git work tree
    completed = subprocess.run(build_ruff_command(sys.executable, str(tmp_path)), capture_output=True, text=True,
                               check=False, timeout=120)
    found = {Path(item["filename"]).name for item in json.loads(completed.stdout)}
    assert found == {"hidden.py", "also_hidden.py"}
