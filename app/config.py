import os
from pathlib import Path
from typing import Any

import yaml


CONFIG_FILENAMES = ("aegis.yml", "aegis.yaml", ".aegis.yml", ".aegis.yaml")
TRUE_VALUES = {"1", "true", "yes", "on"}


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
    if environment != "production":
        return

    errors = []
    try:
        environment_positive_int("AEGIS_MAX_UPLOAD_BYTES", 1024 * 1024)
        environment_positive_int("AEGIS_JOB_LOG_LIMIT", 2000)
        environment_positive_int("AEGIS_JOB_RETENTION_SECONDS", 86400)
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
    if not environment_bool("AEGIS_REQUIRE_AUTH"):
        errors.append("AEGIS_REQUIRE_AUTH must be true")
    if len(os.environ.get("AEGIS_SESSION_SECRET", "")) < 32:
        errors.append("AEGIS_SESSION_SECRET must contain at least 32 characters")
    if len(os.environ.get("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "")) < 12:
        errors.append("AEGIS_BOOTSTRAP_ADMIN_PASSWORD must contain at least 12 characters")
    if len(os.environ.get("AEGIS_METRICS_TOKEN", "")) < 32:
        errors.append("AEGIS_METRICS_TOKEN must contain at least 32 characters")
    setup_token = os.environ.get("AEGIS_SETUP_TOKEN", "")
    if setup_token and len(setup_token) < 32:
        errors.append("AEGIS_SETUP_TOKEN must contain at least 32 characters when set")
    if os.environ.get("AEGIS_GITHUB_CLIENT_ID"):
        if not os.environ.get("AEGIS_GITHUB_CLIENT_SECRET"):
            errors.append("AEGIS_GITHUB_CLIENT_SECRET must be set when GitHub OAuth is enabled")
        if len(os.environ.get("AEGIS_ENCRYPTION_KEY", "")) < 32:
            errors.append("AEGIS_ENCRYPTION_KEY must be a valid Fernet key when GitHub OAuth is enabled")
    if not os.environ.get("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
        errors.append("DATABASE_URL must use PostgreSQL")

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
