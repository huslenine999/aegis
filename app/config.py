from pathlib import Path
from typing import Any

import yaml


CONFIG_FILENAMES = ("aegis.yml", "aegis.yaml", ".aegis.yml", ".aegis.yaml")


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
        return value.lower() in {"1", "true", "yes", "on"}
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
