import json
import os
import subprocess
import sys
from pathlib import Path

import yaml
from fastapi.testclient import TestClient
import pytest

import app.database as database
import app.main as app_main
import app.worker as app_worker
from app.config import validate_runtime_configuration


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_readiness_reports_database_and_redis_state(monkeypatch):
    monkeypatch.delenv("AEGIS_REQUIRE_REDIS", raising=False)
    response = TestClient(app_main.app).get("/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["redis"] in {"connected", "in-memory", "unavailable"}
    assert response.json()["worker"] == "not-required"


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


def test_policy_engine_uses_persistent_data_directory(tmp_path):
    code = """
import json
from policy_engine import SCAN_DIR
print(json.dumps({"scan_dir": str(SCAN_DIR)}))
"""
    environment = {
        **os.environ,
        "AEGIS_DATA_DIR": str(tmp_path),
    }
    environment.pop("SCANS_DIR", None)
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )

    assert json.loads(result.stdout)["scan_dir"] == str(tmp_path / "scans")


def test_worker_dependency_scan_does_not_fall_back_to_project_requirements(tmp_path):
    target = tmp_path / "target"
    target.mkdir()

    assert app_worker._target_requirements_file(target) is None

    (target / "pyproject.toml").write_text('[project]\ndependencies = ["requests==2.34.2"]\n')
    assert app_worker._target_requirements_file(target) is None

    target_requirements = target / "requirements.txt"
    target_requirements.write_text("requests==2.34.2\n")

    assert app_worker._target_requirements_file(target) == target_requirements


def test_worker_mirrors_latest_reports_without_copying_run_workspace(tmp_path, monkeypatch):
    source_dir = tmp_path / "runs" / "job-1"
    source_dir.mkdir(parents=True)
    latest_dir = tmp_path / "latest"
    monkeypatch.setattr(app_worker, "SCANS_DIR", latest_dir)

    (source_dir / "ruff-report.json").write_text("[]")
    (source_dir / "sandbox-status.json").write_text('{"status": "simulated_fallback"}')
    (source_dir / "internal.log").write_text("do not copy")

    app_worker._mirror_latest_reports(source_dir)

    assert (latest_dir / "ruff-report.json").read_text() == "[]"
    assert (latest_dir / "sandbox-status.json").exists()
    assert not (latest_dir / "internal.log").exists()


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
    assert services["dashboard"]["environment"]["AEGIS_ENV"] == "${AEGIS_ENV:-production}"
    assert services["dashboard"]["environment"]["AEGIS_REQUIRE_REDIS"] == "true"
    assert services["dashboard"]["environment"]["AEGIS_REQUIRE_WORKER"] == "true"
    assert services["worker"]["environment"]["AEGIS_DATA_DIR"] == "/data"
    assert "aegis-data:/data" in services["dashboard"]["volumes"]
    assert "aegis-data:/data" in services["worker"]["volumes"]
    assert services["dashboard"]["expose"] == ["5001"]
    assert services["proxy"]["ports"] == ["80:80", "443:443", "443:443/udp"]
    assert services["dashboard"]["environment"]["DATABASE_URL"].startswith("postgresql://")


def test_security_headers_are_added_to_dynamic_responses():
    response = TestClient(app_main.app).get("/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_dashboard_renders_with_current_starlette_template_api():
    response = TestClient(app_main.app).get("/")

    assert response.status_code == 200
    assert "Project Security Dashboard" in response.text


def test_production_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("AEGIS_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("AEGIS_REQUIRE_REDIS", raising=False)
    monkeypatch.delenv("AEGIS_REQUIRE_WORKER", raising=False)

    with pytest.raises(RuntimeError, match="Invalid production configuration"):
        validate_runtime_configuration()


def test_production_configuration_accepts_explicit_secure_values(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setenv("AEGIS_ADMIN_TOKEN", "a" * 32)
    monkeypatch.setenv("AEGIS_ALLOWED_HOSTS", "aegis.example.com")
    monkeypatch.setenv("AEGIS_CORS_ORIGINS", "https://aegis.example.com")
    monkeypatch.setenv("AEGIS_REQUIRE_REDIS", "true")
    monkeypatch.setenv("AEGIS_REQUIRE_WORKER", "true")
    monkeypatch.setenv("AEGIS_REQUIRE_AUTH", "true")
    monkeypatch.setenv("AEGIS_SESSION_SECRET", "s" * 32)
    monkeypatch.setenv("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "test-password-long")
    monkeypatch.setenv("AEGIS_METRICS_TOKEN", "m" * 32)
    monkeypatch.setenv("DATABASE_URL", "postgresql://aegis:test@db/aegis")
    monkeypatch.setenv("AEGIS_ENABLE_DEMO_LAB", "false")

    validate_runtime_configuration()


def test_database_initialization_preserves_existing_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "aegis.db")
    database.initialize_database(reset=True)

    with database.get_connection() as connection:
        connection.execute(
            "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
            ("production-rule", "must survive restart", 1),
        )
        connection.commit()

    database.initialize_database()

    with database.get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM waf_rules WHERE pattern = ?",
            ("production-rule",),
        ).fetchone()[0]
    assert count == 1


def test_database_initialization_records_schema_migration(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "aegis.db")

    database.initialize_database(reset=True)
    database.initialize_database()

    with database.get_connection() as connection:
        rows = connection.execute(
            "SELECT version, name FROM schema_migrations ORDER BY version"
        ).fetchall()

    assert rows == [(database.CURRENT_SCHEMA_VERSION, "initial_schema")]


def test_completed_job_metadata_is_bounded_and_expires(monkeypatch):
    class RecordingRedis:
        def __init__(self):
            self.trimmed = []
            self.expired = []

        def hset(self, *args, **kwargs):
            return 1

        def rpush(self, *args, **kwargs):
            return 1

        def ltrim(self, *args):
            self.trimmed.append(args)

        def publish(self, *args, **kwargs):
            return 1

        def expire(self, *args):
            self.expired.append(args)

    redis_client = RecordingRedis()
    monkeypatch.setattr(app_worker, "redis_client", redis_client)

    app_worker.publish_job_event("job-1", "log", {"text": "line"})
    app_worker.publish_job_event(
        "job-1",
        "state",
        {"state": "completed", "progress": 100},
    )

    assert redis_client.trimmed == [
        ("job_logs:job-1", -app_worker.JOB_LOG_LIMIT, -1),
    ]
    assert len(redis_client.expired) == 2
