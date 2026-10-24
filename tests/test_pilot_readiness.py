import re
import sys

from scripts import pilot_readiness


def test_rehearsal_environment_is_single_tenant_production():
    values = pilot_readiness.production_environment_values()

    assert values["AEGIS_ENV"] == "production"
    assert values["AEGIS_ARTIFACT_BACKEND"] == "local"
    assert values["AEGIS_MULTI_TENANT"] == "false"
    assert values["AEGIS_ALLOW_DEEP_SCANS"] == "false"
    assert len(values["AEGIS_SESSION_SECRET"]) >= 32
    assert "replace-with" not in "\n".join(values.values())


def test_rehearsal_environment_supplies_required_compose_values():
    compose = (pilot_readiness.PROJECT_ROOT / "docker-compose.yml").read_text()
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", compose))
    values = pilot_readiness.production_environment_values()

    assert required <= values.keys()
    assert all(values[name] for name in required)


def test_rehearsal_database_passwords_are_independent_and_url_safe():
    names = ["POSTGRES_PASSWORD", *(f"AEGIS_DB_{role}_PASSWORD" for role in (
        "WORKER", "SIGNER", "BROKER", "NOTIFIER",
    ))]
    first = pilot_readiness.production_environment_values()
    second = pilot_readiness.production_environment_values()
    passwords = [values[name] for values in (first, second) for name in names]

    assert len(set(passwords)) == len(passwords)
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{24,}", password) for password in passwords)


def test_run_check_records_command_failure():
    result, completed = pilot_readiness.run_check(
        "expected failure",
        [sys.executable, "-c", "raise SystemExit(7)"],
        timeout=10,
    )

    assert not result.passed
    assert completed.returncode == 7
    assert result.detail == "exit code 7"


def test_readiness_report_fails_when_any_check_fails():
    report = pilot_readiness.render_report(
        [
            pilot_readiness.CheckResult("good", True, 0.1, "ok"),
            pilot_readiness.CheckResult("bad", False, 0.1, "failed"),
        ],
        docker_smoke=False,
    )

    assert report["schema_version"] == 1
    assert report["passed"] is False
