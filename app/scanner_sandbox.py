"""Run Ruff, Semgrep and detect-secrets in the offline scanner container.

Opt-in with AEGIS_SANDBOX_SCANNERS. When enabled, a missing runtime or image
raises ScannerSandboxError; callers record that as a failed tool, never as a
fallback to an unsandboxed run.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Callable

from .codeql_scanner import _docker_base, _remove_container, _source_tar
from .resource_budgets import run_bounded_subprocess_stdout_to_file


IMAGE_PATTERN = re.compile(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}")
SAFE_ROOT = re.compile(r"/[A-Za-z0-9._/-]+")
CONTAINER_ENVIRONMENT = (
    "HOME=/tmp",
    "SEMGREP_SEND_METRICS=off",
    "SEMGREP_SETTINGS_FILE=/tmp/semgrep-settings.yml",
    "SEMGREP_LOG_FILE=/tmp/semgrep.log",
)


class ScannerSandboxError(RuntimeError):
    """The isolated scanner container cannot be provisioned."""


def sandbox_enabled() -> bool:
    return os.environ.get("AEGIS_SANDBOX_SCANNERS", "false").lower() in {"1", "true", "yes", "on"}


def run_in_sandbox(
    argv: list[str],
    target_path: str | Path,
    stdout_path: Path,
    *,
    timeout: int,
    rules: Path | None = None,
    accepted_return_codes: set[int] | None = None,
    check_callback: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run argv with the scan target extracted at its own path inside the container.

    Reports then carry the same paths as an unsandboxed run. A rules file is
    extracted at its own path, and the command runs from the rules' project root,
    so Semgrep check IDs match an unsandboxed worker run and findings keep their
    fingerprints.
    """
    image = os.environ.get("AEGIS_SCANNER_IMAGE", "").strip()
    if not IMAGE_PATTERN.fullmatch(image):
        raise ScannerSandboxError("Pinned scanner image is not provisioned.")
    docker = shutil.which("docker")
    host = os.environ.get("AEGIS_CODEQL_DOCKER_HOST", "unix:///var/run/docker.sock")
    if not docker or not host.startswith("unix://"):
        raise ScannerSandboxError("Isolated scanners require the Docker CLI and a local Unix socket.")
    try:
        if not stat.S_ISSOCK(Path(host.removeprefix("unix://")).stat().st_mode):
            raise OSError
    except OSError as exc:
        raise ScannerSandboxError("Local Docker socket is unavailable.") from exc
    target = Path(target_path)
    root = target if target.is_dir() else target.parent
    mounted = [root, rules.parent] if rules else [root]
    if any(not path.is_absolute() or not SAFE_ROOT.fullmatch(str(path)) or path == Path("/") for path in mounted):
        raise ScannerSandboxError("Scan target path cannot be mounted in the scanner container.")
    name = f"aegis-scanner-{uuid.uuid4().hex}"
    mounts = ["-i", *(f"--tmpfs={path}:rw,nosuid,nodev,size=2g,mode=1777" for path in mounted)]
    for value in CONTAINER_ENVIRONMENT:
        mounts += ["-e", value]
    # The worker runs Semgrep from the project root, which sets the check-ID prefix.
    cwd = rules.parent.parent if rules else root
    script = f"tar -xf - -C / && cd {shlex.quote(str(cwd))} && exec \"$@\""
    command = _docker_base(Path(docker), image, name, mounts) + ["-ec", script, "sh", *argv]
    with tempfile.TemporaryDirectory(prefix=".aegis-scanner-", dir=stdout_path.parent) as work:
        docker_env = {"PATH": os.defpath, "DOCKER_HOST": host, "DOCKER_CONFIG": work}
        archive = Path(work) / "source.tar"
        _source_tar(target, archive, prefix=str(root).lstrip("/"))
        if rules:
            with tarfile.open(archive, "a") as extra:
                extra.add(rules, arcname=str(rules).lstrip("/"), recursive=False)
        try:
            with archive.open("rb") as stdin:
                return run_bounded_subprocess_stdout_to_file(
                    command, stdout_path, env=docker_env, stdin=stdin, timeout=timeout,
                    accepted_return_codes=accepted_return_codes, check_callback=check_callback,
                )
        finally:
            _remove_container(Path(docker), name, docker_env)
