import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import policies
from app.routes import project_routes


@pytest.fixture(scope="session", autouse=True)
def application_lifespan():
    yield


def test_research_import_cannot_simulate_a_release_policy(monkeypatch):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, *args):
            return self

        def fetchone(self):
            return (json.dumps({"research_only": True}), "quick", "bac-research")

    monkeypatch.setattr(policies, "get_connection", Connection)
    with pytest.raises(ValueError, match="research"):
        policies.simulate_policy(1, 2, policies.DEFAULT_DEFINITION)


def test_research_import_cannot_dispatch_a_source_retry(monkeypatch):
    monkeypatch.setattr(project_routes, "get_scan_run", lambda _: {
        "id": 2, "project_id": 1, "target": "bac-research", "preset": "quick",
    })
    monkeypatch.setattr(project_routes, "_project_access", lambda *args: {"id": 1})
    monkeypatch.setattr(project_routes, "_enqueue_project_scan", lambda *args: pytest.fail("Research import launched a source job"))
    with pytest.raises(HTTPException) as error:
        project_routes.project_scan_retry(2, SimpleNamespace(user_id=10))
    assert error.value.status_code == 409
    assert "research" in error.value.detail.lower()
