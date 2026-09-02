import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .config import config_list
from .scanners import DEFAULT_IGNORED_DIRS
from .scan_engine import exclude_files_pattern
from .safe_output import SafeOutputRoot

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TOOL_TIMEOUT = int(os.environ.get("AEGIS_CLI_TOOL_TIMEOUT", "120"))
IGNORED_DIRS = DEFAULT_IGNORED_DIRS
EXCLUDE_FILES_PATTERN = exclude_files_pattern()
FAST_MODE_SKIPPED_SCANNERS = "Safety/OSV, Semgrep, ClamAV, IaC, Docker sandbox, Trivy, and DAST"
DEFAULT_SCAN_DIR = Path(".aegis") / "scans"
EXIT_ALLOWED = 0
EXIT_BLOCKED = 1
EXIT_OPERATIONAL_ERROR = 2
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
LOCAL_ENV_FILE = PROJECT_ROOT / ".env.aegis"


def should_skip_path(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def get_config_section(config: dict) -> dict:
    section = config.get("scan", {})
    return section if isinstance(section, dict) else {}


def config_value(config: dict, key: str, default=None):
    section = get_config_section(config)
    if key in section:
        return section[key]
    return config.get(key, default)


def get_config_base(config: dict, target_path: Path) -> Path:
    config_base = Path(config.get("_config_path", target_path)).resolve()
    return config_base.parent if config_base.is_file() else config_base


def resolve_exclude_paths(config: dict, target_path: Path) -> set[str]:
    exclude_values = config_list(get_config_section(config), "exclude_paths") or config_list(config, "exclude_paths")
    if not exclude_values:
        return set()

    config_base = Path(config.get("_config_path", target_path)).resolve()
    if config_base.is_file():
        config_base = config_base.parent

    resolved = set()
    for value in exclude_values:
        raw = Path(value)
        resolved.add(str(raw))
        resolved.add(str((config_base / raw).resolve() if not raw.is_absolute() else raw.resolve()))
    return resolved


def is_excluded_path(path: Path, excluded_paths: set[str]) -> bool:
    if not excluded_paths:
        return False
    path_text = str(path)
    resolved_text = str(path.resolve())
    for excluded in excluded_paths:
        if path_text == excluded or path_text.endswith(f"{os.sep}{excluded}"):
            return True
        if path_text.startswith(f"{excluded}{os.sep}"):
            return True
        if resolved_text == excluded or resolved_text.endswith(f"{os.sep}{excluded}"):
            return True
        if resolved_text.startswith(f"{excluded}{os.sep}"):
            return True
    return False


def normalize_suppressions(config: dict, target_path: Path) -> list[dict]:
    raw_items = []
    section = get_config_section(config)
    for value in (config.get("suppressions", []), section.get("suppressions", [])):
        if isinstance(value, list):
            raw_items.extend(value)

    base = get_config_base(config, target_path)
    normalized = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason", "")).strip()
        approved_by = str(item.get("approved_by", "")).strip()
        ticket = str(item.get("ticket", "")).strip()
        expires_at = str(item.get("expires_at", "")).strip()
        validation_errors = []
        expires_at_utc = None
        if len(reason) < 12:
            validation_errors.append("reason must contain at least 12 characters")
        if not approved_by:
            validation_errors.append("approved_by is required")
        if not ticket:
            validation_errors.append("ticket is required")
        if not expires_at:
            validation_errors.append("expires_at is required")
        else:
            try:
                if re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires_at):
                    expires_at_utc = datetime.fromisoformat(
                        f"{expires_at}T23:59:59.999999+00:00"
                    )
                else:
                    expires_at_utc = datetime.fromisoformat(
                        expires_at.replace("Z", "+00:00")
                    )
                    if expires_at_utc.tzinfo is None:
                        expires_at_utc = expires_at_utc.replace(tzinfo=timezone.utc)
                    expires_at_utc = expires_at_utc.astimezone(timezone.utc)
            except ValueError:
                validation_errors.append("expires_at must be an ISO-8601 date or timestamp")
        path_value = item.get("path")
        resolved_path = None
        if path_value:
            path_obj = Path(str(path_value))
            resolved_path = str(path_obj.resolve() if path_obj.is_absolute() else (base / path_obj).resolve())
        status = "invalid" if validation_errors else "active"
        if expires_at_utc and expires_at_utc <= datetime.now(timezone.utc):
            status = "expired"
        normalized.append({
            "tool": str(item.get("tool", "")).lower(),
            "rule": str(item.get("rule", "")).lower(),
            "path": str(path_value) if path_value else "",
            "resolved_path": resolved_path,
            "reason": reason,
            "approved_by": approved_by,
            "ticket": ticket,
            "expires_at": expires_at,
            "status": status,
            "validation_errors": validation_errors,
        })
    return normalized


def suppression_matches(suppression: dict, *, tool: str, rule: str = "", path: str = "") -> bool:
    if suppression.get("status") != "active":
        return False
    tool_value = tool.lower()
    rule_value = str(rule or "").lower()
    path_value = str(path or "")
    resolved_path = str(Path(path_value).resolve()) if path_value else ""

    if suppression["tool"] and suppression["tool"] not in tool_value:
        return False
    if suppression["rule"] and suppression["rule"] != rule_value:
        return False
    if suppression["resolved_path"]:
        expected = suppression["resolved_path"]
        if resolved_path != expected and not resolved_path.endswith(f"{os.sep}{suppression['path']}"):
            return False
    elif suppression["path"] and not path_value.endswith(suppression["path"]):
        return False
    return True


def apply_suppressions(
    scan_dir: Path,
    suppressions: list[dict],
    *,
    safe_output: SafeOutputRoot | None = None,
    read_json_fn=None,
    write_json_fn=None,
):
    if read_json_fn is None or write_json_fn is None:
        from .cli_reports import read_json as default_read_json, write_json as default_write_json
        read_json_fn = read_json_fn or default_read_json
        write_json_fn = write_json_fn or default_write_json

    if not suppressions:
        return

    applied = []
    expired = []
    invalid = []
    for suppression in suppressions:
        evidence = {
            "tool": suppression["tool"],
            "rule": suppression["rule"],
            "path": suppression["path"],
            "reason": suppression["reason"],
            "approved_by": suppression["approved_by"],
            "ticket": suppression["ticket"],
            "expires_at": suppression["expires_at"],
        }
        if suppression["status"] == "expired":
            expired.append(evidence)
        elif suppression["status"] == "invalid":
            invalid.append({**evidence, "validation_errors": suppression["validation_errors"]})

    def suppress_item(tool: str, item: dict, *, rule_keys: tuple[str, ...], path_keys: tuple[str, ...]) -> bool:
        rules: list[str] = []
        for key in rule_keys:
            value = item.get(key)
            if isinstance(value, list):
                rules.extend(str(candidate) for candidate in value if candidate)
            elif value:
                rules.append(str(value))
        if not rules:
            rules.append("")
        path = next((item.get(key) for key in path_keys if item.get(key)), "")
        for suppression in suppressions:
            matched_rule = next(
                (
                    rule
                    for rule in rules
                    if suppression_matches(
                        suppression,
                        tool=tool,
                        rule=rule,
                        path=str(path),
                    )
                ),
                None,
            )
            if matched_rule is not None:
                applied.append({
                    "tool": tool,
                    "rule": matched_rule,
                    "path": path,
                    "reason": suppression["reason"],
                    "approved_by": suppression["approved_by"],
                    "ticket": suppression["ticket"],
                    "expires_at": suppression["expires_at"],
                })
                return True
        return False

    ruff_path = scan_dir / "ruff-report.json"
    if ruff_path.exists() and read_json_fn and write_json_fn:
        ruff = read_json_fn(ruff_path)
        if isinstance(ruff, list):
            ruff = [
                item for item in ruff
                if not suppress_item("Ruff", item, rule_keys=("code",), path_keys=("filename",))
            ]
            write_json_fn(ruff_path, ruff, safe_output=safe_output)

    semgrep_path = scan_dir / "semgrep-report.json"
    if semgrep_path.exists() and read_json_fn and write_json_fn:
        semgrep = read_json_fn(semgrep_path)
        if isinstance(semgrep, dict):
            results = semgrep.get("results", [])
            semgrep["results"] = [
                item for item in results
                if not suppress_item("Semgrep", item, rule_keys=("check_id",), path_keys=("path",))
            ]
            write_json_fn(semgrep_path, semgrep, safe_output=safe_output)

    yara_path = scan_dir / "yara-report.json"
    if yara_path.exists() and read_json_fn and write_json_fn:
        yara = read_json_fn(yara_path)
        if isinstance(yara, list):
            yara = [
                item for item in yara
                if not suppress_item("YARA", item, rule_keys=("rule",), path_keys=("filename",))
            ]
            write_json_fn(yara_path, yara, safe_output=safe_output)

    clamav_path = scan_dir / "clamav-report.json"
    if clamav_path.exists() and read_json_fn and write_json_fn:
        clamav = read_json_fn(clamav_path)
        if isinstance(clamav, list):
            clamav = [
                item for item in clamav
                if not suppress_item("ClamAV", item, rule_keys=("virus",), path_keys=("filename",))
            ]
            write_json_fn(clamav_path, clamav, safe_output=safe_output)

    secrets_path = scan_dir / "secrets-report.json"
    if secrets_path.exists() and read_json_fn and write_json_fn:
        secrets = read_json_fn(secrets_path)
        if isinstance(secrets, dict):
            results = secrets.get("results", {})
            for filename, items in list(results.items()):
                results[filename] = [
                    item for item in items
                    if not suppress_item("Secrets", {**item, "filename": filename}, rule_keys=("type",), path_keys=("filename",))
                ]
                if not results[filename]:
                    del results[filename]
            write_json_fn(secrets_path, secrets, safe_output=safe_output)

    osv_path = scan_dir / "osv-report.json"
    if osv_path.exists() and read_json_fn and write_json_fn:
        osv = read_json_fn(osv_path)
        if isinstance(osv, list):
            osv = [
                item for item in osv
                if not suppress_item(
                    "OSV Dependency Audit",
                    item,
                    rule_keys=("id", "aliases"),
                    path_keys=(),
                )
            ]
            write_json_fn(osv_path, osv, safe_output=safe_output)

    iac_path = scan_dir / "iac-report.json"
    if iac_path.exists() and read_json_fn and write_json_fn:
        iac = read_json_fn(iac_path)
        if isinstance(iac, dict):
            findings = iac.get("findings", [])
            if isinstance(findings, list):
                iac["findings"] = [
                    item for item in findings
                    if not suppress_item(
                        "IaC",
                        item,
                        rule_keys=("rule_id", "check_id"),
                        path_keys=("path",),
                    )
                ]
            unmanaged = iac.get("unmanaged_suppressions", [])
            if isinstance(unmanaged, list):
                governed = []
                for item in unmanaged:
                    if suppress_item(
                        "IaC",
                        item,
                        rule_keys=("rule_id", "check_id"),
                        path_keys=("path",),
                    ):
                        continue
                    governed.append(item)
                iac["unmanaged_suppressions"] = governed
            write_json_fn(iac_path, iac, safe_output=safe_output)

    if write_json_fn:
        write_json_fn(
            scan_dir / "suppressions-report.json",
            {
                "schema_version": 2,
                "applied": applied,
                "expired": expired,
                "invalid": invalid,
            },
            safe_output=safe_output,
        )


def validate_fail_on(value: str | None) -> str | None:
    if value is None:
        return None
    severities = {
        severity.strip().upper()
        for severity in str(value).split(",")
        if severity.strip()
    }
    invalid = sorted(severities - VALID_SEVERITIES)
    if invalid:
        raise ValueError(
            f"Unsupported --fail-on severity: {', '.join(invalid)}. "
            f"Expected a comma-separated subset of: {', '.join(sorted(VALID_SEVERITIES))}."
        )
    if not severities:
        raise ValueError("--fail-on must contain at least one severity.")
    return ",".join(sorted(severities))
