"""Opt-in PostgreSQL backup and restore rehearsal for the production Compose stack."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest


pytestmark = pytest.mark.integration
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _compose_command() -> list[str]:
    command = ["docker", "compose"]
    command.extend(["-f", "docker-compose.yml"])
    ci_override = PROJECT_ROOT / "docker-compose.ci.yml"
    if ci_override.exists():
        command.extend(["-f", str(ci_override)])
    project_name = os.environ.get("AEGIS_COMPOSE_PROJECT", "").strip()
    if project_name:
        command.extend(["--project-name", project_name])
    return command


def _run_compose(*arguments: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*_compose_command(), *arguments],
        cwd=PROJECT_ROOT,
        input=input_bytes,
        capture_output=True,
        check=False,
        timeout=180,
    )


def _enabled() -> bool:
    return os.environ.get("AEGIS_COMPOSE_INTEGRATION", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def test_compose_plain_sql_backup_restores_marker() -> None:
    if not _enabled():
        pytest.skip("Compose integration tests are disabled.")

    marker_key = f"compose_recovery_{uuid4().hex}"
    marker_sql = (
        "INSERT INTO application_state (state_key, state_value, updated_at) "
        f"VALUES ('{marker_key}', 'verified', CURRENT_TIMESTAMP::text);"
    )
    delete_sql = f"DELETE FROM application_state WHERE state_key='{marker_key}';"
    seeded = _run_compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "aegis",
        "-d",
        "aegis",
        "-c",
        marker_sql,
    )
    assert seeded.returncode == 0, seeded.stderr.decode(errors="replace")

    try:
        dump = _run_compose(
            "exec",
            "-T",
            "postgres",
            "pg_dump",
            "--clean",
            "--if-exists",
            "--format=plain",
            "-U",
            "aegis",
            "-d",
            "aegis",
        )
        assert dump.returncode == 0, dump.stderr.decode(errors="replace")
        assert b"PostgreSQL database dump" in dump.stdout[:500]

        stopped = _run_compose("stop", "dashboard", "worker", "notifier")
        assert stopped.returncode == 0, stopped.stderr.decode(errors="replace")

        deleted = _run_compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "aegis",
            "-d",
            "aegis",
            "-c",
            delete_sql,
        )
        assert deleted.returncode == 0, deleted.stderr.decode(errors="replace")

        restored = _run_compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "aegis",
            "-d",
            "aegis",
            input_bytes=dump.stdout,
        )
        assert restored.returncode == 0, restored.stderr.decode(errors="replace")

        verified = _run_compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "aegis",
            "-d",
            "aegis",
            "-tA",
            "-c",
            f"SELECT state_value FROM application_state WHERE state_key='{marker_key}';",
        )
        assert verified.returncode == 0, verified.stderr.decode(errors="replace")
        assert verified.stdout.decode().strip() == "verified"
    finally:
        _run_compose("up", "-d", "dashboard", "worker", "notifier")
        _run_compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "aegis",
            "-d",
            "aegis",
            "-c",
            delete_sql,
        )
