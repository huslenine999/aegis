"""Run PostgreSQL-specific paths against a real server when one is supplied.

Set AEGIS_TEST_POSTGRES_URL to an empty, disposable database, for example:

    AEGIS_TEST_POSTGRES_URL=postgresql://aegis@127.0.0.1:5432/aegis_test pytest tests/integration/test_postgres_paths.py

The checks run in a child process because app.database selects its backend at
import time, and the rest of the suite uses SQLite.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

POSTGRES_URL = os.environ.get("AEGIS_TEST_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="AEGIS_TEST_POSTGRES_URL is not set")
ROOT = Path(__file__).resolve().parents[2]


def test_postgres_migrations_audit_findings_and_signer():
    environment = {
        **os.environ,
        "DATABASE_URL": POSTGRES_URL,
        "AEGIS_ENV": "development",
        "AEGIS_AUDIT_HMAC_KEY": "a" * 40,
    }
    environment.pop("AEGIS_EVIDENCE_SIGNING_KEY", None)
    completed = subprocess.run(
        [sys.executable, "-m", "tests.integration.postgres_paths"],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300, check=False,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    passed = json.loads(completed.stdout.strip().splitlines()[-1])["passed"]
    assert "signer signs on PostgreSQL" in passed
    assert "checkpoint detects truncation" in passed


def test_each_service_runs_under_its_least_privilege_login(tmp_path):
    from urllib.parse import urlsplit, urlunsplit

    from cryptography.fernet import Fernet

    owner = urlsplit(POSTGRES_URL)
    passwords = {name: f"{name.lower()}-test-password-0123456789" for name in ("WORKER", "SIGNER", "BROKER", "NOTIFIER")}
    logins = {"worker": ("aegis_worker", "WORKER"), "signer": ("aegis_signer", "SIGNER"),
              "broker": ("aegis_github_broker", "BROKER"), "notifier": ("aegis_notifier", "NOTIFIER")}
    base = {
        **os.environ,
        "AEGIS_ENV": "development",
        "AEGIS_DATA_DIR": str(tmp_path),
        "AEGIS_AUDIT_HMAC_KEY": "a" * 40,
        "AEGIS_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "AEGIS_REQUIRE_NOTIFIER": "true",
        "AEGIS_ENABLE_YARA": "false",
        "AEGIS_SKIP_EXTERNAL_SCANNERS": "true",
        "REDIS_URL": "redis://127.0.0.1:1/0",
        **{f"AEGIS_DB_{name}_PASSWORD": value for name, value in passwords.items()},
    }
    base.pop("AEGIS_EVIDENCE_SIGNING_KEY", None)

    def run(phase, url):
        completed = subprocess.run(
            [sys.executable, "-m", "tests.integration.postgres_roles", phase],
            cwd=ROOT, env={**base, "DATABASE_URL": url}, capture_output=True, text=True, timeout=300, check=False,
        )
        assert completed.returncode == 0, f"{phase} failed:\n{completed.stderr[-4000:]}"
        return json.loads(completed.stdout.strip().splitlines()[-1])["passed"]

    passed = run("owner", POSTGRES_URL)
    for phase, (login, key) in logins.items():
        netloc = f"{login}:{passwords[key]}@{owner.hostname}:{owner.port or 5432}"
        passed += run(phase, urlunsplit((owner.scheme, netloc, owner.path, "", "")))
    assert "worker: completed a real scan" in passed
    assert "signer: signs as a least-privilege login" in passed
    assert "broker: scoped installation token" in passed
    assert "notifier: delivered with decrypted config" in passed
    assert sum("cannot drop triggers" in name for name in passed) == 4
