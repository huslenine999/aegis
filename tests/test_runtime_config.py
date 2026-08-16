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


def test_security_txt_exposes_disclosure_policy_without_authentication(monkeypatch):
    monkeypatch.setenv("AEGIS_PUBLIC_URL", "https://aegis.example.com")
    response = TestClient(app_main.app).get("/.well-known/security.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "Contact: https://github.com/huslenine999/aegis/security/advisories/new" in response.text
    assert "Policy: https://github.com/huslenine999/aegis/security/policy" in response.text
    assert "Canonical: https://aegis.example.com/.well-known/security.txt" in response.text


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
    assert paths["db_path"] == str(tmp_path / "aegis.db")
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


def test_application_factory_returns_route_bearing_app(tmp_path, monkeypatch):
    from app.main import create_app
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    application = create_app()
    with TestClient(application) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200
        assert client.get("/api/projects").status_code == 200


def test_importing_main_does_not_create_runtime_database(tmp_path):
    code = """
from app.database import DB_PATH
import app.main
print(DB_PATH.exists())
"""
    environment = {
        **os.environ,
        "AEGIS_DATA_DIR": str(tmp_path),
        "AEGIS_ENV": "test",
        "AEGIS_ENABLE_DEMO_LAB": "false",
        "REDIS_URL": "redis://127.0.0.1:6399/0",
    }
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip().splitlines()[-1] == "False"


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


def test_worker_rejects_symlinked_latest_report_source(tmp_path, monkeypatch):
    source_dir = tmp_path / "runs" / "job-1"
    source_dir.mkdir(parents=True)
    latest_dir = tmp_path / "latest"
    outside = tmp_path / "outside.json"
    outside.write_text('{"secret": true}')
    (source_dir / "ruff-report.json").symlink_to(outside)
    monkeypatch.setattr(app_worker, "SCANS_DIR", latest_dir)

    with pytest.raises(RuntimeError, match="symbolic links"):
        app_worker._mirror_latest_reports(source_dir)
    assert not (latest_dir / "ruff-report.json").exists()


def test_container_runtime_is_hardened_and_persistent():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text()
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text())
    services = compose["services"]

    assert "FROM python:3.11.15-slim-bookworm@sha256:" in dockerfile
    assert "uv==0.11.25" in dockerfile
    assert "uv sync --locked" in dockerfile
    assert "/usr/local/bin/python -m pip uninstall -y uv" in dockerfile
    assert "USER aegis" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "AEGIS_ENV=production" in dockerfile
    assert "AEGIS_REQUIRE_AUTH=true" in dockerfile
    assert "AEGIS_CORS_ORIGINS=" not in dockerfile
    assert 'ENTRYPOINT ["python", "-m", "app.preflight"]' in dockerfile
    assert 'CMD ["uvicorn", "app.main:app"' in dockerfile

    assert "ports" not in services["redis"]
    assert services["redis"]["read_only"] is True
    assert services["dashboard"]["read_only"] is True
    assert services["worker"]["read_only"] is True
    assert services["dashboard"]["environment"]["AEGIS_DATA_DIR"] == "/data"
    assert services["dashboard"]["environment"]["AEGIS_ENV"] == "${AEGIS_ENV:-production}"
    assert services["dashboard"]["environment"]["AEGIS_REQUIRE_REDIS"] == "true"
    assert services["dashboard"]["environment"]["AEGIS_REQUIRE_WORKER"] == "true"
    assert services["dashboard"]["environment"]["AEGIS_REQUIRE_NOTIFIER"] == "true"
    assert services["dashboard"]["environment"]["AEGIS_ARTIFACT_BACKEND"] == "${AEGIS_ARTIFACT_BACKEND:-local}"
    assert services["worker"]["environment"]["AEGIS_DATA_DIR"] == "/data"
    assert services["worker"]["environment"]["AEGIS_ARTIFACT_BACKEND"] == "${AEGIS_ARTIFACT_BACKEND:-local}"
    assert "AEGIS_SMTP_PASSWORD" not in services["dashboard"]["environment"]
    assert "AEGIS_SMTP_PASSWORD" not in services["worker"]["environment"]
    assert "AEGIS_SMTP_PASSWORD" in services["notifier"]["environment"]
    assert "aegis-data:/data" in services["dashboard"]["volumes"]
    assert "aegis-data:/data" in services["worker"]["volumes"]
    assert services["dashboard"]["expose"] == ["5001"]
    assert services["proxy"]["ports"] == ["80:80", "443:443", "443:443/udp"]
    assert services["dashboard"]["environment"]["DATABASE_URL"].startswith("postgresql://")
    assert services["dashboard"]["environment"]["FORWARDED_ALLOW_IPS"] != "*"
    assert "AEGIS_ADMIN_TOKEN" not in services["dashboard"]["environment"]
    assert "AEGIS_SESSION_SECRET" not in services["worker"]["environment"]
    assert "AEGIS_ADMIN_TOKEN" not in services["worker"]["environment"]
    assert services["worker"]["entrypoint"] == [
        "python",
        "-m",
        "app.worker_entrypoint",
    ]
    assert services["worker"]["command"][:2] == ["--url", "redis://redis:6379/0"]
    assert services["notifier"]["entrypoint"] == [
        "python",
        "-m",
        "app.notifier_entrypoint",
    ]
    assert services["notifier"]["command"][:2] == ["--url", "redis://redis:6379/0"]
    assert services["postgres"]["image"].endswith(
        "@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa"
    )
    assert services["proxy"]["image"].endswith(
        "@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c"
    )
    assert services["worker"]["healthcheck"]["test"][0] == "CMD"
    assert "Worker.all" in services["worker"]["healthcheck"]["test"][-1]
    assert services["notifier"]["healthcheck"]["test"][0] == "CMD"
    assert "notifications" in services["notifier"]["healthcheck"]["test"][-1]
    assert services["proxy"]["depends_on"]["dashboard"]["condition"] == "service_started"


def test_dependency_workflow_uses_locked_python_and_node_installs():
    package = json.loads((PROJECT_ROOT / "package.json").read_text())
    package_lock = json.loads((PROJECT_ROOT / "package-lock.json").read_text())
    dependabot = yaml.safe_load((PROJECT_ROOT / ".github/dependabot.yml").read_text())
    security_workflow = (PROJECT_ROOT / ".github/workflows/security-pipeline.yml").read_text()
    release_workflow = (PROJECT_ROOT / ".github/workflows/release-build.yml").read_text()

    assert package["engines"]["node"] == ">=18.0.0"
    assert package_lock["packages"][""]["engines"]["node"] == ">=18.0.0"
    assert "npm ci" in security_workflow
    assert "npm install" not in security_workflow
    assert "uv sync --locked" in security_workflow
    assert "uv pip check" in security_workflow
    assert "python -m pip check" not in security_workflow
    assert "uv sync --locked" in release_workflow
    assert "uv pip check" in release_workflow
    assert "python -m pip check" not in release_workflow
    assert "python -m pip wheel" not in security_workflow
    assert "python -m pip wheel" not in release_workflow
    assert "uv build --wheel --out-dir dist" in security_workflow
    assert "uv build --wheel --out-dir dist" in release_workflow
    assert "::add-mask::$value" in security_workflow
    assert "uv.lock" in security_workflow
    assert {item["package-ecosystem"] for item in dependabot["updates"]} >= {
        "docker",
        "github-actions",
        "npm",
        "pip",
    }


def test_container_preflight_rejects_missing_production_configuration(monkeypatch):
    from app.preflight import validate_startup_configuration

    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setenv("AEGIS_HOST", "0.0.0.0")
    for name in (
        "AEGIS_ALLOWED_HOSTS",
        "AEGIS_AUDIT_HMAC_KEY",
        "AEGIS_BOOTSTRAP_ADMIN_PASSWORD",
        "AEGIS_CORS_ORIGINS",
        "AEGIS_ENCRYPTION_KEY",
        "AEGIS_METRICS_TOKEN",
        "AEGIS_PUBLIC_URL",
        "AEGIS_REQUIRE_AUTH",
        "AEGIS_REQUIRE_NOTIFIER",
        "AEGIS_REQUIRE_REDIS",
        "AEGIS_REQUIRE_WORKER",
        "AEGIS_SESSION_SECRET",
        "AEGIS_TOKEN_PEPPER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AEGIS_ENABLE_DEMO_LAB", "false")

    with pytest.raises(RuntimeError, match="Invalid production configuration"):
        validate_startup_configuration()


def test_security_headers_are_added_to_dynamic_responses():
    response = TestClient(app_main.app).get("/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "script-src-attr 'none'" in response.headers["content-security-policy"]
    assert "script-src 'self' 'nonce-" in response.headers["content-security-policy"]
    assert "script-src 'self' 'unsafe-inline'" not in response.headers["content-security-policy"]


def test_dashboard_renders_with_current_starlette_template_api():
    response = TestClient(app_main.app).get("/")

    assert response.status_code == 200
    assert "Release security, in context." in response.text
    assert str(response.url).endswith("/projects")


def test_production_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("AEGIS_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("AEGIS_REQUIRE_REDIS", raising=False)
    monkeypatch.delenv("AEGIS_REQUIRE_WORKER", raising=False)
    monkeypatch.delenv("AEGIS_REQUIRE_NOTIFIER", raising=False)

    with pytest.raises(RuntimeError, match="Invalid production configuration"):
        validate_runtime_configuration()


def test_production_configuration_accepts_explicit_secure_values(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setenv("AEGIS_ALLOWED_HOSTS", "aegis.example.com")
    monkeypatch.setenv("AEGIS_CORS_ORIGINS", "https://aegis.example.com")
    monkeypatch.setenv("AEGIS_PUBLIC_URL", "https://aegis.example.com")
    monkeypatch.setenv("AEGIS_REQUIRE_REDIS", "true")
    monkeypatch.setenv("AEGIS_REQUIRE_WORKER", "true")
    monkeypatch.setenv("AEGIS_REQUIRE_NOTIFIER", "true")
    monkeypatch.setenv("AEGIS_REQUIRE_AUTH", "true")
    monkeypatch.setenv("AEGIS_SESSION_SECRET", "s" * 32)
    monkeypatch.setenv("AEGIS_TOKEN_PEPPER", "p" * 32)
    monkeypatch.setenv("AEGIS_AUDIT_HMAC_KEY", "a" * 32)
    monkeypatch.setenv(
        "AEGIS_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
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

    assert rows == [
        (migration.version, migration.name) for migration in database.MIGRATIONS
    ]


def test_production_database_does_not_seed_legacy_api_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "production.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setenv("AEGIS_ENV", "production")

    database.initialize_database(reset=True)

    with database.get_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_development_demo_users_receive_generated_api_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "development.db")
    monkeypatch.setattr(database, "USING_POSTGRES", False)
    monkeypatch.setenv("AEGIS_ENV", "development")

    database.initialize_database(reset=True)

    with database.get_connection() as connection:
        keys = [row[0] for row in connection.execute("SELECT api_key FROM users")]

    assert len(keys) == 3
    assert len(set(keys)) == 3
    assert all(len(key) >= 32 for key in keys)
    assert not {"ADMIN-API-KEY-12345", "DEV-API-KEY-67890", "GUEST-API-KEY-00000"} & set(keys)


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
