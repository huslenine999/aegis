"""Random requests to every route must never crash Aegis or cross an access boundary.

Deeper runs: AEGIS_MONKEY_REQUESTS=20000 AEGIS_MONKEY_SEED=7 pytest tests/test_api_monkey.py
(add AEGIS_TEST_POSTGRES_URL to run against an empty PostgreSQL database).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_random_requests_never_crash_or_cross_access_boundaries():
    requests = os.environ.get("AEGIS_MONKEY_REQUESTS", "500")
    seed = os.environ.get("AEGIS_MONKEY_SEED", "20261016")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AEGIS_")}
    if os.environ.get("AEGIS_TEST_POSTGRES_URL"):
        environment["AEGIS_TEST_POSTGRES_URL"] = os.environ["AEGIS_TEST_POSTGRES_URL"]
    completed = subprocess.run(
        [sys.executable, "-m", "tests.api_monkey", requests, seed],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=600, check=False,
    )
    assert completed.stdout, completed.stderr[-4000:]
    summary = json.loads(completed.stdout.strip().splitlines()[-1])
    assert summary["failures"] == [], json.dumps(summary["failures"], indent=2)
    assert completed.returncode == 0
    # The run must get past authentication and validation, not only collect 401s.
    assert summary["routes_reached"] >= 25
    assert set(summary["viewer_writes"]) <= {
        "POST /api/auth/login", "POST /api/auth/logout", "POST /api/auth/reauth", "POST /api/github/disconnect",
        "POST /api/projects/{project_id}/policies/simulate",
    }
