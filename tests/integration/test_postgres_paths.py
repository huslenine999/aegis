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
