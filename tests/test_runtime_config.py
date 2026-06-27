import json
import os
import subprocess
import sys
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

import app.main as app_main


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_readiness_reports_database_and_redis_state(monkeypatch):
    monkeypatch.delenv("AEGIS_REQUIRE_REDIS", raising=False)
    response = TestClient(app_main.app).get("/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["redis"] in {"connected", "in-memory", "unavailable"}


def test_readiness_fails_when_required_redis_is_unavailable(monkeypatch):
    monkeypatch.setenv("AEGIS_REQUIRE_REDIS", "true")
    monkeypatch.setattr(app_main, "REDIS_AVAILABLE", False)
    response = TestClient(app_main.app).get("/ready")

    assert response.status_code == 503
    assert response.json()["detail"] == "Redis is required but unavailable."


def test_data_directory_does_not_replace_source_root(tmp_path):
    code = """
import json
from app.database import DB_PATH, DOWNLOAD_DIR, PROJECT_ROOT, SCANS_DIR
print(json.dumps({
    "project_root": str(PROJECT_ROOT),
    "db_path": str(DB_PATH),
    "download_dir": str(DOWNLOAD_DIR),
    "scans_dir": str(SCANS_DIR),
}))
"""
    environment = {**os.environ, "AEGIS_DATA_DIR": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    paths = json.loads(result.stdout)

    assert paths["project_root"] == str(PROJECT_ROOT)
    assert paths["db_path"] == str(tmp_path / "aegis_demo.db")
    assert paths["download_dir"] == str(tmp_path / "downloads")
    assert paths["scans_dir"] == str(tmp_path / "scans")


def test_container_runtime_is_hardened_and_persistent():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text()
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())
    services = compose["services"]

    assert "FROM python:3.11.15-slim-bookworm@sha256:" in dockerfile
    assert "USER aegis" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert 'CMD ["uvicorn", "app.main:app"' in dockerfile

    assert "ports" not in services["redis"]
    assert services["redis"]["read_only"] is True
    assert services["dashboard"]["read_only"] is True
    assert services["worker"]["read_only"] is True
    assert services["dashboard"]["environment"]["AEGIS_DATA_DIR"] == "/data"
    assert services["worker"]["environment"]["AEGIS_DATA_DIR"] == "/data"
    assert "aegis-data:/data" in services["dashboard"]["volumes"]
    assert "aegis-data:/data" in services["worker"]["volumes"]
    assert services["dashboard"]["ports"] == ["127.0.0.1:5001:5001"]
