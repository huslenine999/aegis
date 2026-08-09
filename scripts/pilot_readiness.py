#!/usr/bin/env python3
"""Produce a reproducible Aegis pilot-readiness report.

The default run is non-destructive: it compiles the project, runs the quality
and behavior suites, validates the production Compose configuration, and writes
a machine-readable report. ``--docker-smoke`` additionally creates an isolated
Compose project, verifies health/readiness, rehearses PostgreSQL backup/restore,
restarts the application services, and removes only that temporary project.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TIMEOUT = 300
REHEARSAL_SERVICES = {"postgres", "redis", "dashboard", "worker", "notifier", "proxy"}


@dataclass
class CheckResult:
    name: str
    passed: bool
    duration_seconds: float
    detail: str


def production_environment_values() -> dict[str, str]:
    """Return non-placeholder secrets for an isolated localhost rehearsal."""
    return {
        "AEGIS_ENV": "production",
        "AEGIS_DOMAIN": "localhost",
        "AEGIS_ALLOWED_HOSTS": "localhost,127.0.0.1",
        "AEGIS_CORS_ORIGINS": "https://localhost",
        "AEGIS_ADMIN_TOKEN": secrets.token_urlsafe(40),
        "AEGIS_SESSION_SECRET": secrets.token_urlsafe(48),
        "AEGIS_TOKEN_PEPPER": secrets.token_urlsafe(48),
        "AEGIS_AUDIT_HMAC_KEY": secrets.token_urlsafe(48),
        "AEGIS_SECURITY_PROFILE": "standard",
        "AEGIS_REQUIRE_NOTIFIER": "true",
        "AEGIS_BOOTSTRAP_ADMIN_USERNAME": "admin",
        "AEGIS_BOOTSTRAP_ADMIN_PASSWORD": "",
        "AEGIS_SETUP_TOKEN": secrets.token_urlsafe(48),
        "AEGIS_ENCRYPTION_KEY": base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode(),
        "AEGIS_GITHUB_CLIENT_ID": "",
        "AEGIS_GITHUB_CLIENT_SECRET": "",
        "AEGIS_GITHUB_CALLBACK_URL": "",
        "AEGIS_GITHUB_APP_ID": "",
        "AEGIS_GITHUB_APP_PRIVATE_KEY_B64": "",
        "AEGIS_GITHUB_WEBHOOK_SECRET": secrets.token_urlsafe(40),
        "AEGIS_SMTP_HOST": "",
        "AEGIS_SMTP_PORT": "587",
        "AEGIS_SMTP_USERNAME": "",
        "AEGIS_SMTP_PASSWORD": "",
        "AEGIS_SMTP_FROM": "aegis@example.invalid",
        "AEGIS_METRICS_TOKEN": secrets.token_urlsafe(40),
        "AEGIS_ARTIFACT_BACKEND": "local",
        "AEGIS_ALLOW_DEEP_SCANS": "false",
        "AEGIS_ISOLATED_WORKER": "false",
        "AEGIS_MULTI_TENANT": "false",
        "AEGIS_ENABLE_SAFETY": "false",
        "SAFETY_API_KEY": "",
        "AEGIS_EVIDENCE_SIGNING_KEY": base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode().rstrip("="),
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
    }


def write_environment_file(path: Path, values: dict[str, str]) -> None:
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    os.chmod(path, 0o600)


def concise_output(completed: subprocess.CompletedProcess, limit: int = 2000) -> str:
    def decode(value) -> str:
        if isinstance(value, bytes):
            return value.decode(errors="replace")
        return str(value or "")

    output = "\n".join(
        item.strip()
        for item in (decode(completed.stdout), decode(completed.stderr))
        if item and item.strip()
    )
    if not output:
        return f"exit code {completed.returncode}"
    return output[-limit:]


def run_check(
    name: str,
    command: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    environment: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
) -> tuple[CheckResult, subprocess.CompletedProcess]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=environment,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        result = CheckResult(
            name=name,
            passed=completed.returncode == 0,
            duration_seconds=round(time.monotonic() - started, 3),
            detail=concise_output(completed),
        )
        return result, completed
    except (OSError, subprocess.TimeoutExpired) as exc:
        result = CheckResult(
            name=name,
            passed=False,
            duration_seconds=round(time.monotonic() - started, 3),
            detail=str(exc),
        )
        return result, subprocess.CompletedProcess(command, 1, b"", str(exc).encode())


def docker_compose_base(environment_file: Path, project_name: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        project_name,
        "--project-directory",
        str(PROJECT_ROOT),
        "--env-file",
        str(environment_file),
    ]


def ports_are_available(ports: tuple[int, ...] = (80, 443)) -> bool:
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return False
    return True


def wait_for_endpoint(url: str, timeout: int = 180) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    context = ssl._create_unverified_context()  # localhost Caddy rehearsal certificate
    last_error = "endpoint did not respond"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5, context=context) as response:
                body = response.read().decode(errors="replace")
                if response.status == 200:
                    return True, body[:1000]
                last_error = f"HTTP {response.status}: {body[:500]}"
        except (OSError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(2)
    return False, last_error


def static_checks(*, skip_docker: bool) -> list[CheckResult]:
    python = sys.executable
    commands = [
        ("git whitespace", ["git", "diff", "--check"], 60),
        (
            "compile",
            [python, "-m", "compileall", "-q", "app", "policy_engine.py", "tests"],
            120,
        ),
        ("ruff", [python, "-m", "ruff", "check", "app", "policy_engine.py", "tests", "scripts"], 180),
        ("mypy", [python, "-m", "mypy"], 300),
        (
            "pytest",
            [python, "-m", "pytest", "-q", "--timeout=60", "--timeout-method=thread"],
            600,
        ),
        (
            "scanner benchmark",
            [python, "scripts/run_security_benchmark.py", "--output", os.devnull],
            300,
        ),
    ]
    results = [run_check(name, command, timeout=timeout)[0] for name, command, timeout in commands]

    if skip_docker:
        results.append(CheckResult("compose configuration", True, 0.0, "skipped by request"))
        return results
    if shutil.which("docker") is None:
        results.append(CheckResult("compose configuration", False, 0.0, "docker is not installed"))
        return results

    with tempfile.TemporaryDirectory(prefix="aegis-pilot-config-") as temporary:
        environment_file = Path(temporary) / "rehearsal.env"
        write_environment_file(environment_file, production_environment_values())
        command = [
            *docker_compose_base(environment_file, "aegis-pilot-config"),
            "config",
            "--quiet",
        ]
        results.append(run_check("compose configuration", command, timeout=120)[0])
    return results


def docker_rehearsal() -> list[CheckResult]:
    results: list[CheckResult] = []
    if shutil.which("docker") is None:
        return [CheckResult("docker rehearsal", False, 0.0, "docker is not installed")]
    if not ports_are_available():
        return [
            CheckResult(
                "docker rehearsal",
                False,
                0.0,
                "ports 80 or 443 are in use; refusing to disturb an existing service",
            )
        ]

    project_name = f"aegis-pilot-{secrets.token_hex(4)}"
    with tempfile.TemporaryDirectory(prefix="aegis-pilot-rehearsal-") as temporary:
        environment_file = Path(temporary) / "rehearsal.env"
        write_environment_file(environment_file, production_environment_values())
        compose = docker_compose_base(environment_file, project_name)
        started = False
        try:
            check, _ = run_check(
                "docker build and start",
                [*compose, "up", "--build", "--detach"],
                timeout=900,
            )
            results.append(check)
            if not check.passed:
                return results
            started = True

            health_ok, health_detail = wait_for_endpoint("https://localhost/health")
            ready_ok, ready_detail = wait_for_endpoint("https://localhost/ready")
            results.append(CheckResult("dashboard health", health_ok, 0.0, health_detail))
            results.append(CheckResult("dependency readiness", ready_ok, 0.0, ready_detail))
            if not health_ok or not ready_ok:
                return results

            service_check, service_process = run_check(
                "service topology",
                [*compose, "ps", "--status", "running", "--services"],
                timeout=60,
            )
            running = set((service_process.stdout or b"").decode().split())
            missing = sorted(REHEARSAL_SERVICES - running)
            if missing:
                service_check.passed = False
                service_check.detail = "missing running services: " + ", ".join(missing)
            results.append(service_check)
            if not service_check.passed:
                return results

            marker_sql = (
                "INSERT INTO application_state (state_key, state_value, updated_at) "
                "VALUES ('pilot_rehearsal_marker', 'verified', CURRENT_TIMESTAMP::text) "
                "ON CONFLICT (state_key) DO UPDATE SET state_value='verified', "
                "updated_at=CURRENT_TIMESTAMP::text;"
            )
            marker_check, _ = run_check(
                "seed recovery marker",
                [*compose, "exec", "-T", "postgres", "psql", "-U", "aegis", "-d", "aegis", "-c", marker_sql],
                timeout=60,
            )
            results.append(marker_check)
            if not marker_check.passed:
                return results

            dump_check, dump_process = run_check(
                "database backup",
                [
                    *compose,
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
                ],
                timeout=180,
            )
            results.append(dump_check)
            if not dump_check.passed:
                return results

            quiesce_check, _ = run_check(
                "quiesce application services",
                [*compose, "stop", "dashboard", "worker", "notifier"],
                timeout=180,
            )
            results.append(quiesce_check)
            if not quiesce_check.passed:
                return results

            delete_check, _ = run_check(
                "mutate rehearsal state",
                [*compose, "exec", "-T", "postgres", "psql", "-U", "aegis", "-d", "aegis", "-c", "DELETE FROM application_state WHERE state_key='pilot_rehearsal_marker';"],
                timeout=60,
            )
            results.append(delete_check)
            if not delete_check.passed:
                return results

            restore_check, _ = run_check(
                "database restore",
                [*compose, "exec", "-T", "postgres", "psql", "-U", "aegis", "-d", "aegis"],
                timeout=180,
                input_bytes=dump_process.stdout or b"",
            )
            results.append(restore_check)
            if not restore_check.passed:
                return results

            verify_check, verify_process = run_check(
                "verify restored state",
                [*compose, "exec", "-T", "postgres", "psql", "-U", "aegis", "-d", "aegis", "-tA", "-c", "SELECT state_value FROM application_state WHERE state_key='pilot_rehearsal_marker';"],
                timeout=60,
            )
            if (verify_process.stdout or b"").decode().strip() != "verified":
                verify_check.passed = False
                verify_check.detail = "recovery marker was not restored"
            results.append(verify_check)

            restart_check, _ = run_check(
                "application recovery start",
                [*compose, "up", "--detach", "dashboard", "worker", "notifier"],
                timeout=180,
            )
            results.append(restart_check)
            if restart_check.passed:
                ready_ok, ready_detail = wait_for_endpoint("https://localhost/ready")
                results.append(CheckResult("post-restart readiness", ready_ok, 0.0, ready_detail))
        finally:
            if started:
                cleanup, _ = run_check(
                    "rehearsal cleanup",
                    [*compose, "down", "--volumes", "--remove-orphans"],
                    timeout=300,
                )
                results.append(cleanup)
    return results


def render_report(results: list[CheckResult], *, docker_smoke: bool) -> dict:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(PROJECT_ROOT),
        "docker_rehearsal_requested": docker_smoke,
        "passed": all(result.passed for result in results),
        "checks": [asdict(result) for result in results],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Aegis controlled-pilot readiness")
    parser.add_argument("--output", help="Write the JSON report to this path")
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Skip Docker Compose configuration validation",
    )
    parser.add_argument(
        "--docker-smoke",
        action="store_true",
        help="Run an isolated Docker deployment, recovery, restart, and cleanup rehearsal",
    )
    arguments = parser.parse_args()

    results = static_checks(skip_docker=arguments.skip_docker)
    if arguments.docker_smoke and all(result.passed for result in results):
        results.extend(docker_rehearsal())
    report = render_report(results, docker_smoke=arguments.docker_smoke)
    encoded = json.dumps(report, indent=2) + "\n"
    if arguments.output:
        output = Path(arguments.output).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)
    print(encoded, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
