import os
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from cryptography.fernet import Fernet


CONFIG_FILENAMES = ("aegis.yml", "aegis.yaml", ".aegis.yml", ".aegis.yaml")
TRUE_VALUES = {"1", "true", "yes", "on"}


def validate_server_bind(host: str, *, auth_required: bool) -> str:
    normalized = host.strip().lower().strip("[]")
    if not normalized:
        raise RuntimeError("AEGIS_HOST must not be empty.")
    is_loopback = normalized == "localhost"
    try:
        is_loopback = is_loopback or ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        pass
    if not is_loopback and not auth_required:
        raise RuntimeError(
            "Refusing to expose Aegis on a non-loopback interface while authentication "
            "is disabled. Set AEGIS_REQUIRE_AUTH=true or bind AEGIS_HOST to localhost."
        )
    return host


def find_config(start_path: str | Path) -> Path | None:
    current = Path(start_path).expanduser().resolve()
    if current.is_file():
        current = current.parent

    for directory in (current, *current.parents):
        for filename in CONFIG_FILENAMES:
            candidate = directory / filename
            if candidate.exists():
                return candidate
    return None


def load_config(start_path: str | Path, explicit_path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(explicit_path).expanduser().resolve() if explicit_path else find_config(start_path)
    if not config_path or not config_path.exists():
        return {}

    try:
        data = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid Aegis YAML config {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Aegis config must be a mapping: {config_path}")
    data["_config_path"] = str(config_path)
    return data


def config_bool(config: dict[str, Any], key: str, default: bool = False) -> bool:
    value = config.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in TRUE_VALUES
    return bool(value)


def config_list(config: dict[str, Any], key: str) -> list[str]:
    value = config.get(key, [])
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ValueError(f"Aegis config key '{key}' must be a list or comma-separated string.")


def environment_bool(key: str, default: bool = False) -> bool:
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


def environment_list(key: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(key, default).split(",") if item.strip()]


def environment_positive_int(key: str, default: int) -> int:
    raw_value = os.environ.get(key, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(f"{key} must be a positive integer.") from exc
    if value < 1:
        raise RuntimeError(f"{key} must be a positive integer.")
    return value


def validate_runtime_configuration() -> None:
    environment = os.environ.get("AEGIS_ENV", "development").strip().lower()
    if environment not in {"development", "test", "production"}:
        raise RuntimeError("AEGIS_ENV must be development, test, or production.")
    security_profile = os.environ.get("AEGIS_SECURITY_PROFILE", "standard").strip().lower()
    if security_profile not in {"standard", "bank"}:
        raise RuntimeError("AEGIS_SECURITY_PROFILE must be standard or bank.")
    if security_profile == "bank":
        raise RuntimeError(
            "AEGIS_SECURITY_PROFILE=bank is fail-closed in this build: an external OIDC "
            "identity provider, KMS-backed secret provider, isolated scanner service, "
            "immutable object-storage adapter, and durable SIEM exporter are not all "
            "implemented. Use the standard single-tenant profile or supply those adapters "
            "before representing this service as bank-grade."
        )
    if environment != "production":
        return

    errors = []
    try:
        environment_positive_int("AEGIS_MAX_UPLOAD_BYTES", 1024 * 1024)
        environment_positive_int("AEGIS_MAX_REQUEST_BYTES", 1024 * 1024 + 64 * 1024)
        environment_positive_int("AEGIS_JOB_LOG_LIMIT", 2000)
        environment_positive_int("AEGIS_JOB_RETENTION_SECONDS", 86400)
        environment_positive_int("AEGIS_ARTIFACT_RETENTION_DAYS", 30)
        environment_positive_int("AEGIS_SCAN_JOB_TIMEOUT_SECONDS", 3600)
        environment_positive_int("AEGIS_SANDBOX_COMMAND_TIMEOUT_SECONDS", 300)
        environment_positive_int("AEGIS_SCANNER_TIMEOUT_SECONDS", 300)
        environment_positive_int("AEGIS_LOGIN_FAILURE_LIMIT", 5)
        environment_positive_int("AEGIS_LOGIN_LOCKOUT_SECONDS", 900)
        environment_positive_int("AEGIS_RECENT_AUTH_SECONDS", 600)
        environment_positive_int("AEGIS_SANDBOX_MAX_FILES", 100000)
        environment_positive_int("AEGIS_SANDBOX_MAX_CONTEXT_BYTES", 2 * 1024 * 1024 * 1024)
    except RuntimeError as exc:
        errors.append(str(exc))
    admin_token = os.environ.get("AEGIS_ADMIN_TOKEN", "")
    if len(admin_token) < 32:
        errors.append("AEGIS_ADMIN_TOKEN must contain at least 32 characters")
    if environment_bool("AEGIS_ENABLE_DEMO_LAB"):
        errors.append("AEGIS_ENABLE_DEMO_LAB must be false")
    if not environment_bool("AEGIS_REQUIRE_REDIS"):
        errors.append("AEGIS_REQUIRE_REDIS must be true")
    if not environment_bool("AEGIS_REQUIRE_WORKER"):
        errors.append("AEGIS_REQUIRE_WORKER must be true")
    if not environment_bool("AEGIS_REQUIRE_NOTIFIER"):
        errors.append("AEGIS_REQUIRE_NOTIFIER must be true")
    if not environment_bool("AEGIS_REQUIRE_AUTH"):
        errors.append("AEGIS_REQUIRE_AUTH must be true")
    if len(os.environ.get("AEGIS_SESSION_SECRET", "")) < 32:
        errors.append("AEGIS_SESSION_SECRET must contain at least 32 characters")
    if len(os.environ.get("AEGIS_TOKEN_PEPPER", "")) < 32:
        errors.append("AEGIS_TOKEN_PEPPER must contain at least 32 characters")
    if len(os.environ.get("AEGIS_AUDIT_HMAC_KEY", "")) < 32:
        errors.append("AEGIS_AUDIT_HMAC_KEY must contain at least 32 characters")
    encryption_key = os.environ.get("AEGIS_ENCRYPTION_KEY", "")
    try:
        Fernet(encryption_key.encode())
    except (ValueError, TypeError):
        errors.append("AEGIS_ENCRYPTION_KEY must be a valid Fernet key")
    bootstrap_password = os.environ.get("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "")
    if len(os.environ.get("AEGIS_METRICS_TOKEN", "")) < 32:
        errors.append("AEGIS_METRICS_TOKEN must contain at least 32 characters")
    setup_token = os.environ.get("AEGIS_SETUP_TOKEN", "")
    if setup_token and len(setup_token) < 32:
        errors.append("AEGIS_SETUP_TOKEN must contain at least 32 characters when set")
    if not setup_token and len(bootstrap_password) < 12:
        errors.append(
            "AEGIS_BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters "
            "when AEGIS_SETUP_TOKEN is not set"
        )
    elif bootstrap_password and len(bootstrap_password) < 12:
        errors.append("AEGIS_BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters")
    if os.environ.get("AEGIS_GITHUB_CLIENT_ID"):
        if not os.environ.get("AEGIS_GITHUB_CLIENT_SECRET"):
            errors.append("AEGIS_GITHUB_CLIENT_SECRET must be set when GitHub OAuth is enabled")
    github_webhook_secret = os.environ.get("AEGIS_GITHUB_WEBHOOK_SECRET", "")
    if github_webhook_secret and len(github_webhook_secret) < 32:
        errors.append("AEGIS_GITHUB_WEBHOOK_SECRET must contain at least 32 characters")
    if os.environ.get("AEGIS_GITHUB_APP_ID") and len(github_webhook_secret) < 32:
        errors.append("AEGIS_GITHUB_WEBHOOK_SECRET is required when the GitHub App is enabled")
    if os.environ.get("AEGIS_GITHUB_APP_ID") and not (
        os.environ.get("AEGIS_GITHUB_APP_PRIVATE_KEY")
        or os.environ.get("AEGIS_GITHUB_APP_PRIVATE_KEY_B64")
    ):
        errors.append(
            "AEGIS_GITHUB_APP_PRIVATE_KEY_B64 is required when the GitHub App is enabled"
        )
    if environment_bool("AEGIS_ALLOW_DEEP_SCANS") and not environment_bool(
        "AEGIS_ISOLATED_WORKER"
    ):
        errors.append(
            "AEGIS_ISOLATED_WORKER must be true when deep scans are enabled in production"
        )
    if environment_bool("AEGIS_MULTI_TENANT"):
        errors.append(
            "AEGIS_MULTI_TENANT must remain false until an external tenant-scoped object storage backend is configured"
        )
    if not os.environ.get("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
        errors.append("DATABASE_URL must use PostgreSQL")
    public_url = os.environ.get("AEGIS_PUBLIC_URL", "")
    parsed_public_url = urlparse(public_url)
    if (
        parsed_public_url.scheme != "https"
        or not parsed_public_url.hostname
        or parsed_public_url.username
        or parsed_public_url.password
        or parsed_public_url.path not in {"", "/"}
        or parsed_public_url.query
        or parsed_public_url.fragment
    ):
        errors.append("AEGIS_PUBLIC_URL must be an absolute HTTPS origin")

    origins = environment_list("AEGIS_CORS_ORIGINS")
    if not origins:
        errors.append("AEGIS_CORS_ORIGINS must contain at least one explicit origin")
    elif "*" in origins:
        errors.append("AEGIS_CORS_ORIGINS cannot contain '*'")

    allowed_hosts = environment_list("AEGIS_ALLOWED_HOSTS")
    if not allowed_hosts:
        errors.append("AEGIS_ALLOWED_HOSTS must contain at least one explicit host")
    elif "*" in allowed_hosts:
        errors.append("AEGIS_ALLOWED_HOSTS cannot contain '*'")

    if errors:
        raise RuntimeError("Invalid production configuration: " + "; ".join(errors) + ".")
