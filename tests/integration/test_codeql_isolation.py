"""Opt-in Docker-level isolation checks for the Deep (CodeQL) analysis container.

Probes run inside the provisioned CodeQL image with the exact flags Aegis uses
for analysis. Enable with AEGIS_CODEQL_ISOLATION=1 after `make codeql-setup`;
once enabled, a missing image or Docker runtime fails instead of skipping.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from app.codeql_scanner import _docker_base


pytestmark = pytest.mark.integration
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CANARY = "AEGIS_ISOLATION_CANARY"
PROBE = r'''
import json, os, socket, subprocess


def attempt(action):
    try:
        action()
        return "allowed"
    except OSError as exc:
        return f"{type(exc).__name__}:{exc.errno}"


def write(path):
    with open(path, "w") as handle:
        handle.write("probe")


def up_interfaces():
    # Kernels with tunnel modules add idle gre0/sit0/... devices to every
    # network namespace; only interfaces that are up can carry traffic.
    names = []
    for name in sorted(os.listdir("/sys/class/net")):
        try:
            flags = int(open(f"/sys/class/net/{name}/flags").read(), 16)
        except OSError:
            continue  # e.g. bonding_masters is a file, not a device
        if flags & 1:
            names.append(name)
    return names


def first_readable(*paths):
    for path in paths:
        try:
            return open(path).read().strip()
        except OSError:
            pass
    return None


status = dict(line.split(":\t", 1) for line in open("/proc/self/status").read().splitlines() if ":\t" in line)
mountinfo = [line.split() for line in open("/proc/self/mountinfo")]
report = {
    "uid": os.getuid(),
    "cap_eff": status["CapEff"].strip(),
    "no_new_privs": status["NoNewPrivs"].strip(),
    "up_interfaces": up_interfaces(),
    "ipv4_routes": len(open("/proc/net/route").read().splitlines()) - 1,
    "tcp_egress": attempt(lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close()),
    "tcp6_egress": attempt(lambda: socket.create_connection(("2606:4700:4700::1111", 443), timeout=3).close()),
    "dns": attempt(lambda: socket.getaddrinfo("github.com", 443)),
    "root_options": next(fields[5] for fields in mountinfo if fields[4] == "/").split(","),
    "image_write": attempt(lambda: write("/opt/codeql/.aegis-probe")),
    "work_write": attempt(lambda: write("/work/probe")),
    "work_entries": sorted(os.listdir("/work")),
    "mounts": sorted({fields[4] for fields in mountinfo}),
    "environment": sorted(os.environ),
    "processes": sorted(int(name) for name in os.listdir("/proc") if name.isdigit()),
    "docker_socket": os.path.exists("/var/run/docker.sock"),
    "memory_limit": first_readable("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"),
}
children = []
try:
    for _ in range(200):
        children.append(subprocess.Popen(["sleep", "30"]))
except OSError as exc:
    report["spawn_error"] = exc.errno
finally:
    for child in children:
        child.kill()
        child.wait()
report["spawned"] = len(children)
print(json.dumps(report))
'''
EXPECTED_MOUNTS = {"/", "/work", "/tmp", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}


@pytest.fixture
def runtime(tmp_path) -> tuple[Path, str, dict[str, str]]:
    if os.environ.get("AEGIS_CODEQL_ISOLATION", "").lower() not in {"1", "true", "yes", "on"}:
        pytest.skip("CodeQL isolation checks are disabled.")
    image = os.environ.get("AEGIS_CODEQL_IMAGE", "")
    env_file = PROJECT_ROOT / ".env.aegis"
    if not image and env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("AEGIS_CODEQL_IMAGE="):
                image = line.partition("=")[2].strip().strip("\"'")
    if not re.fullmatch(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
        pytest.fail("Isolation checks are enabled, but no digest-pinned AEGIS_CODEQL_IMAGE is provisioned.")
    docker = shutil.which("docker")
    if not docker:
        pytest.fail("Isolation checks are enabled, but the Docker CLI is not installed.")
    host = os.environ.get("AEGIS_CODEQL_DOCKER_HOST") or subprocess.run(
        [docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        capture_output=True, text=True, timeout=30, check=True,
    ).stdout.strip()
    # The same client environment as app.codeql_scanner, plus a canary that must not cross.
    environment = {"PATH": os.defpath, "DOCKER_HOST": host, "DOCKER_CONFIG": str(tmp_path), CANARY: "must-not-cross"}
    return Path(docker), image, environment


def _probe(runtime) -> dict:
    docker, image, environment = runtime
    command = _docker_base(docker, image, f"aegis-isolation-{uuid.uuid4().hex}", ["-i"]) + ["-c", "exec python3 -"]
    completed = subprocess.run(command, input=PROBE, capture_output=True, text=True, env=environment, timeout=180)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_analysis_container_has_no_egress_credentials_or_writable_image(runtime) -> None:
    report = _probe(runtime)

    # One comparison, so a failure lists every check that differs.
    observed = {
        "uid": report["uid"],
        "cap_eff": report["cap_eff"],
        "no_new_privs": report["no_new_privs"],
        "up_interfaces": report["up_interfaces"],
        "ipv4_routes": report["ipv4_routes"],
        "tcp_egress_blocked": report["tcp_egress"] != "allowed",
        "tcp6_egress_blocked": report["tcp6_egress"] != "allowed",
        "dns_blocked": report["dns"] != "allowed",
        "root_read_only": "ro" in report["root_options"],
        "image_write": report["image_write"],
        "work_write": report["work_write"],
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
        "tcp6_egress_blocked": True,
        "dns_blocked": True,
        "root_read_only": True,
        "image_write": "OSError:30",  # EROFS: the image layer is read-only
        "work_write": "allowed",
        "docker_socket": False,
        "unexpected_mounts": [],
        "leaked_environment": [],
        "memory_limit": str(4 * 1024**3),
        "process_limit_hit": True,
    }


def test_concurrent_analysis_containers_cannot_see_each_other(runtime) -> None:
    docker, image, environment = runtime
    name = f"aegis-isolation-{uuid.uuid4().hex}"
    other_run = subprocess.Popen(
        _docker_base(docker, image, name, []) + ["-c", "echo other-run > /work/marker && exec sleep 60"],
        env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            running = subprocess.run(
                [str(docker), "inspect", "--format", "{{.State.Running}}", name],
                capture_output=True, text=True, env=environment, timeout=30,
            )
            if running.stdout.strip() == "true":
                break
            time.sleep(1)
        else:
            pytest.fail("The concurrent analysis container did not start.")
        report = _probe(runtime)
        assert report["work_entries"] == ["probe"]
        assert report["processes"] == [1]
    finally:
        subprocess.run([str(docker), "rm", "-f", name], capture_output=True, env=environment, timeout=60)
        other_run.wait(timeout=60)
