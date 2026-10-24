"""Run the browser-test app with one deterministic repository clone fixture."""

import os
import tempfile
from pathlib import Path

import uvicorn

from app import worker
from app.main import app


FIXTURE_REPOSITORY = "https://github.com/aegis-e2e/scan-fixture.git"
FIXTURE_SOURCE = """import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.get('/users')
def users():
    connection = sqlite3.connect(':memory:')
    name = request.args.get('name', '')
    return str(connection.execute(f\"SELECT * FROM users WHERE name = '{name}'\").fetchall())
"""


def main() -> None:
    if os.environ.get("AEGIS_ENV") != "test":
        raise RuntimeError("The browser fixture server requires AEGIS_ENV=test.")
    clone_repository = worker._clone_github_project

    def clone_fixture(project, *args, **kwargs):
        if project["repository_url"] != FIXTURE_REPOSITORY:
            return clone_repository(project, *args, **kwargs)
        source = Path(tempfile.mkdtemp(prefix="aegis-e2e-source-"))
        (source / "fixture.py").write_text(FIXTURE_SOURCE, encoding="utf-8")
        return str(source), source

    worker._clone_github_project = clone_fixture
    uvicorn.run(app, host="127.0.0.1", port=5011)


if __name__ == "__main__":
    main()
