import pytest

from app.scan_status import ToolStatusTracker


def test_tool_status_tracker_updates_existing_record():
    tracker = ToolStatusTracker()

    tracker.mark("Ruff", "failed", detail="invalid report", return_code=2)
    tracker.mark("Ruff", "completed", return_code=0)
    tracker.mark("Semgrep", "skipped", detail="fast mode")

    assert tracker.records == [
        {"name": "Ruff", "status": "completed", "return_code": 0},
        {"name": "Semgrep", "status": "skipped", "detail": "fast mode"},
    ]
    assert tracker.failures() == []
    assert tracker.states() == {"Ruff": "completed", "Semgrep": "skipped"}
    assert tracker.has("Semgrep")


def test_tool_status_tracker_rejects_unknown_state():
    tracker = ToolStatusTracker()

    with pytest.raises(ValueError):
        tracker.mark("Ruff", "unknown")
