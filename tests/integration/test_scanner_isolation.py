"""Opt-in Docker-level isolation checks for the sandboxed scanner container.

Same probe and flags as the CodeQL checks, run in the scanner image. Enable with
AEGIS_SCANNER_ISOLATION=1 after `make scanner-setup`; once enabled, a missing
image or Docker runtime fails instead of skipping.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from app.codeql_scanner import _docker_base
from app.scanner_sandbox import run_in_sandbox
from tests.integration.test_codeql_isolation import CANARY, EXPECTED_MOUNTS, PROBE


pytestmark = pytest.mark.integration
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCANNER_PROBE = PROBE.replace("/opt/codeql/.aegis-probe", "/usr/local/.aegis-probe")


@pytest.fixture
def runtime(tmp_path, monkeypatch) -> tuple[Path, str, dict[str, str]]:
    if os.environ.get("AEGIS_SCANNER_ISOLATION", "").lower() not in {"1", "true", "yes", "on"}:
        pytest.skip("Scanner isolation checks are disabled.")
    image = os.environ.get("AEGIS_SCANNER_IMAGE", "")
    env_file = PROJECT_ROOT / ".env.aegis"
    if not image and env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("AEGIS_SCANNER_IMAGE="):
                image = line.partition("=")[2].strip().strip("\"'")
    if not re.fullmatch(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
        pytest.fail("Isolation checks are enabled, but no digest-pinned AEGIS_SCANNER_IMAGE is provisioned.")
    docker = shutil.which("docker")
    if not docker:
        pytest.fail("Isolation checks are enabled, but the Docker CLI is not installed.")
    host = os.environ.get("AEGIS_CODEQL_DOCKER_HOST") or subprocess.run(
        [docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        capture_output=True, text=True, timeout=30, check=True,
    ).stdout.strip()
    monkeypatch.setenv("AEGIS_SCANNER_IMAGE", image)
    monkeypatch.setenv("AEGIS_CODEQL_DOCKER_HOST", host)
    environment = {"PATH": os.defpath, "DOCKER_HOST": host, "DOCKER_CONFIG": str(tmp_path), CANARY: "must-not-cross"}
    return Path(docker), image, environment


def _probe(runtime, drop: str | None = None) -> dict:
    docker, image, environment = runtime
    base = _docker_base(docker, image, f"aegis-isolation-{uuid.uuid4().hex}", ["-i"])
    command = [part for part in base if part != drop] + ["-c", "exec python3 -"]
    completed = subprocess.run(command, input=SCANNER_PROBE, capture_output=True, text=True, env=environment, timeout=180)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_scanner_container_has_no_egress_credentials_or_writable_image(runtime) -> None:
    report = _probe(runtime)

    observed = {
        "uid": report["uid"],
        "cap_eff": report["cap_eff"],
        "no_new_privs": report["no_new_privs"],
        "up_interfaces": report["up_interfaces"],
        "ipv4_routes": report["ipv4_routes"],
        "tcp_egress_blocked": report["tcp_egress"] != "allowed",
        "dns_blocked": report["dns"] != "allowed",
        "root_read_only": "ro" in report["root_options"],
        "image_write": report["image_write"],
        "docker_socket": report["docker_socket"],
        "unexpected_mounts": [
            mount for mount in report["mounts"]
            if mount not in EXPECTED_MOUNTS and not mount.startswith(("/proc", "/sys", "/dev"))
        ],
        "leaked_environment": [
            name for name in report["environment"]
            if name == CANARY or name.startswith(("AEGIS_", "GITHUB_", "DOCKER_", "POSTGRES", "REDIS", "DATABASE"))
        ],
        "memory_limit": report["memory_limit"],
        "process_limit_hit": report["spawned"] < 128 and report.get("spawn_error") is not None,
    }
    assert observed == {
        "uid": 10001,
        "cap_eff": "0000000000000000",
        "no_new_privs": "1",
        "up_interfaces": ["lo"],
        "ipv4_routes": 0,
        "tcp_egress_blocked": True,
        "dns_blocked": True,
        "root_read_only": True,
        "image_write": "OSError:30",
        "docker_socket": False,
        "unexpected_mounts": [],
        "leaked_environment": [],
        "memory_limit": str(4 * 1024**3),
        "process_limit_hit": True,
    }


def test_probe_detects_missing_network_and_read_only_flags(runtime) -> None:
    # Negative controls: the probe must fail when a protection is removed.
    assert _probe(runtime, drop="--network=none")["up_interfaces"] != ["lo"]
    assert "ro" not in _probe(runtime, drop="--read-only")["root_options"]


def test_sandboxed_run_cannot_reach_host_secrets_or_write_back(runtime, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(CANARY, "must-not-cross")
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n")
    output = tmp_path / "out.json"
    script = (
        "import json, os, socket\n"
        "open('escaped.txt', 'w').write('x')\n"
        "try:\n    socket.create_connection(('1.1.1.1', 443), timeout=3); net = 'allowed'\n"
        "except OSError:\n    net = 'blocked'\n"
        "print(json.dumps({'canary': os.environ.get(%r), 'net': net, 'files': sorted(os.listdir('.'))}))\n" % CANARY
    )
    completed = run_in_sandbox(["python", "-c", script], source, output, timeout=120)

    assert completed.returncode == 0
    assert json.loads(output.read_text()) == {"canary": None, "net": "blocked", "files": ["a.py", "escaped.txt"]}
    assert not (source / "escaped.txt").exists()
