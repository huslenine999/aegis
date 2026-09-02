"""Shared scan job contracts and lifecycle/event adapters.

The CLI and RQ worker still own their environment-specific orchestration, but
they now exchange the same immutable job payload and lifecycle primitives.
This keeps queue serialization, status tracking, and event delivery from
drifting while the scanner phases are migrated into this module incrementally.
"""

import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable, Mapping, Protocol

from .scanners import DEFAULT_IGNORED_DIRS
from .scan_status import ToolStatusTracker


def exclude_files_pattern(
    ignored_dirs: Iterable[str] | None = None,
) -> str:
    """Build the detect-secrets ``--exclude-files`` regex shared by CLI and worker."""
    names = sorted(ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS)
    return rf"(^|/)({'|'.join(re.escape(name) for name in names)})(/|$)"


EXCLUDE_FILES_PATTERN = exclude_files_pattern()


def add_semgrep_excludes(
    command: list[str],
    ignored_dirs: Iterable[str] | None = None,
) -> list[str]:
    """Append one ``--exclude`` flag per ignored directory, in a stable order."""
    for ignored_dir in sorted(ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS):
        command.extend(["--exclude", ignored_dir])
    return command


@dataclass(frozen=True)
class ScanJobPayload:
    """The versioned payload accepted by both local and RQ scan execution."""

    job_id: str
    target: str
    custom_file_path: str | None = None
    waf_enabled: bool = False
    scan_run_id: int | None = None
    project_id: int | None = None
    requested_by: int | None = None
    preset: str = "standard"
    source_revision: str | None = None
    github_installation_id: int | None = None
    diff_aware: bool = False

    def as_rq_kwargs(self) -> dict[str, Any]:
        """Return a stable, explicit representation for queue diagnostics."""
        return asdict(self)


@dataclass(frozen=True)
class ScanEvent:
    event_type: str
    data: Mapping[str, Any]


class ScanEventSink(Protocol):
    def emit(self, event: ScanEvent) -> None:
        """Deliver one scan lifecycle event."""


def publish_job_event(job_id: str, event_type: str, data: dict[str, Any]) -> None:
    """Lazy bridge to the worker's Redis publisher without an import cycle."""
    from .worker import publish_job_event as worker_publish_job_event

    worker_publish_job_event(job_id, event_type, data)


class RedisEventSink:
    def __init__(self, job_id: str):
        self.job_id = job_id

    def emit(self, event: ScanEvent) -> None:
        publish_job_event(self.job_id, event.event_type, dict(event.data))


class CliEventSink:
    def __init__(self, callback: Callable[[ScanEvent], None]):
        self._callback = callback

    def emit(self, event: ScanEvent) -> None:
        self._callback(event)


class ScanRunner:
    """Shared lifecycle/status coordinator for CLI and worker adapters."""

    def __init__(
        self,
        event_sink: ScanEventSink,
        tool_statuses: ToolStatusTracker | None = None,
    ):
        self.event_sink = event_sink
        self.tool_statuses = (
            tool_statuses if tool_statuses is not None else ToolStatusTracker()
        )

    def transition(self, state: str, progress: int) -> None:
        self.event_sink.emit(
            ScanEvent("state", {"state": state, "progress": progress})
        )

    def log(self, text: str, *, level: str = "info") -> None:
        self.event_sink.emit(ScanEvent("log", {"text": text, "level": level}))

    def mark_tool(
        self,
        name: str,
        status: str,
        *,
        detail: str | None = None,
        return_code: int | None = None,
    ) -> None:
        self.tool_statuses.mark(
            name,
            status,
            detail=detail,
            return_code=return_code,
        )
        data: dict[str, Any] = {"name": name, "status": status}
        if detail is not None:
            data["detail"] = detail
        if return_code is not None:
            data["return_code"] = return_code
        self.event_sink.emit(ScanEvent("tool", data))
