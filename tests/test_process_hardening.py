"""Scanner subprocesses cannot read a hardened worker's environment."""

import os
import subprocess
import sys

import pytest

PROBE = """
import sys
try:
    data = open('/proc/%d/environ', 'rb').read()
    print('READ' if b'aegis-probe-secret' in data else 'READ-WITHOUT-SECRET')
except OSError:
    print('DENIED')
"""

PARENT = """
import subprocess, sys
from app.process_hardening import deny_same_user_inspection
harden = sys.argv[1] == "harden"
if harden:
    assert deny_same_user_inspection()
probe = sys.argv[2] % __import__('os').getpid()
# The scanner gets an empty environment, as scanner_subprocess_environment() does.
print(subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env={}).stdout.strip())
"""


def run_parent(mode):
    environment = {**os.environ, "AEGIS_PROBE_SECRET": "aegis-probe-secret"}
    completed = subprocess.run(
        [sys.executable, "-c", PARENT, mode, PROBE],
        capture_output=True, text=True, env=environment, timeout=60, check=True,
    )
    return completed.stdout.strip()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux /proc semantics")
def test_scanner_child_can_read_an_unhardened_parent_but_not_a_hardened_one():
    assert run_parent("plain") == "READ"
    assert run_parent("harden") == "DENIED"


def test_scan_worker_hardens_itself_before_running_jobs(monkeypatch):
    from app import worker

    calls = []
    monkeypatch.setattr(worker, "deny_same_user_inspection", lambda: calls.append(True) or True)
    monkeypatch.setattr(worker.Worker, "__init__", lambda self, *args, **kwargs: None)

    worker.ScanWorker(["default"])

    assert calls == [True]
