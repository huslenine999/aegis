"""Shared scan job contracts and lifecycle/event adapters.

The CLI and RQ worker still own their environment-specific orchestration, but
they now exchange the same immutable job payload and lifecycle primitives.
This keeps queue serialization, status tracking, and event delivery from
drifting while the scanner phases are migrated into this module incrementally.
"""

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from .scanners import DEFAULT_IGNORED_DIRS
from .scan_status import ToolStatusTracker


# Profile semantics changed when the Deep scanner set switched to CodeQL.
# Persist this alongside run results so historical Deep runs remain distinct.
SCAN_PROFILE_VERSION = 2

# File types covered by rules/semgrep_rules.yaml.
SEMGREP_SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".go", ".java",
})


def exclude_files_pattern(
    ignored_dirs: Iterable[str] | None = None,
) -> str:
    """Build the detect-secrets ``--exclude-files`` regex shared by CLI and worker."""
    names = sorted(ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS)
    return rf"(^|/)({'|'.join(re.escape(name) for name in names)})(/|$)"


EXCLUDE_FILES_PATTERN = exclude_files_pattern()
# The scanned repository must not allowlist its own secrets with inline
# "pragma: allowlist secret" comments; reviewed exceptions belong in trusted config.
DETECT_SECRETS_TRUSTED_FLAGS = (
    "--disable-filter", "detect_secrets.filters.allowlist.is_line_allowlisted",
    # A whole line that only pins a GitHub Action or checkout to a commit SHA holds no secret.
    "--exclude-lines", r'''^\s*(-\s*)?(uses:\s*["']?[\w.-]+/[\w./-]+@|ref:\s*["']?)[0-9a-f]{40}["']?(\s+#\s*[\w.-]*)?\s*$''',
)


def detect_secrets_target(target_path: str | Path) -> tuple[Path, str]:
    """Return (working directory, path argument) for a detect-secrets scan.

    detect-secrets silently skips every file outside its working directory, so
    it must run from the scan root. Run it with ``python -I`` so the scanned
    tree, now the working directory, cannot shadow the detect_secrets module.
    """
    target = Path(target_path)
    return (target, ".") if target.is_dir() else (target.parent, target.name)


# The Semgrep release pinned in pyproject.toml (scanner extra); `aegis doctor` warns on others.
SEMGREP_VERSION = "1.179.0"
# The scanned repository must not choose what Semgrep skips: ignore its
# ``nosemgrep`` comments and ``.semgrepignore`` files, and do not silently skip
# large files (a slow file becomes a Timeout error instead; see
# scanners.semgrep_coverage_gaps). Pinned Semgrep supports the ``--x-`` flag.
SEMGREP_TRUSTED_TARGETING = ("--disable-nosem", "--x-ignore-semgrepignore-files", "--max-target-bytes=0")
# Semgrep's own default .semgrepignore, applied by Aegis instead of the repository,
# minus its test paths: a repository must not hide code by naming a folder ``tests``.
SEMGREP_DEFAULT_EXCLUDES = (
    ".git", ".svn", "_darcs", "build/", "vendor/", "dist/", "*.min.js", ".env/", ".tox/", "node_modules/",
    ".npm/", ".yarn/", ".venv/", "_opam/", "_build/", "_cargo/",
)


def add_semgrep_excludes(
    command: list[str],
    ignored_dirs: Iterable[str] | None = None,
) -> list[str]:
    """Append Aegis's trusted Semgrep target selection, in a stable order."""
    command.extend(SEMGREP_TRUSTED_TARGETING)
    for pattern in SEMGREP_DEFAULT_EXCLUDES:
        command.extend(["--exclude", pattern])
    for ignored_dir in sorted(ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS):
        command.extend(["--exclude", ignored_dir])
    return command


def build_ruff_command(
    python_executable: str,
    target_path: str,
    excluded_paths: Iterable[str] = (),
) -> list[str]:
    """Build the trusted Ruff command used for both CLI and queued scans.

    The repository being inspected is attacker-controlled.  Ruff must not load
    configuration from that repository or honor inline ``noqa`` directives,
    otherwise the target can change the detector policy while still returning a
    successful scan exit code.
    """

    command = [
        python_executable,
        "-m",
        "ruff",
        "check",
        "--isolated",
        "--ignore-noqa",
        # .gitignore and .ignore files in the target would otherwise hide files.
        "--no-respect-gitignore",
        "--no-cache",
        "--select",
        "S",
        "--output-format",
        "json",
        target_path,
    ]
    excluded = sorted(set(excluded_paths))
    if excluded:
        command.extend(["--exclude", ",".join(excluded)])
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
