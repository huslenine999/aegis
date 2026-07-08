import os
import sys
import json
import uuid
import shutil
import socket
import subprocess
import contextlib
import importlib.metadata
import re
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "app"))

from policy_engine import run_policy_engine, query_osv_vulnerabilities
from config import config_bool, config_list, load_config
from dependencies import discover_dependency_manifests, first_requirements_manifest
from scanners import run_clamav_scan as shared_run_clamav_scan
from scanners import run_yara_scan as shared_run_yara_scan
from scanners import configure_semgrep_environment
from scanners import write_semgrep_rules
import cli_stack
from sandbox import (
    is_docker_available, scaffold_sandbox_context, build_sandbox_image,
    run_sandbox_container, wait_for_container, run_trivy_scan, stop_and_cleanup_sandbox
)

DEFAULT_TOOL_TIMEOUT = int(os.environ.get("AEGIS_CLI_TOOL_TIMEOUT", "120"))
IGNORED_DIRS = {
    ".aegis",
    ".antigravitycli",
    ".git",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "scanner-venv",
    "scans",
    "venv",
}
EXCLUDE_FILES_PATTERN = rf"(^|/)({'|'.join(re.escape(name) for name in sorted(IGNORED_DIRS))})(/|$)"
FAST_MODE_SKIPPED_SCANNERS = "Safety/OSV, Semgrep, ClamAV, Docker sandbox, Trivy, and DAST"
DEFAULT_SCAN_DIR = Path(".aegis") / "scans"
EXIT_ALLOWED = 0
EXIT_BLOCKED = 1
EXIT_OPERATIONAL_ERROR = 2
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
LOCAL_ENV_FILE = PROJECT_ROOT / ".env.aegis"


def should_skip_path(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def add_semgrep_excludes(command: list[str]) -> list[str]:
    for ignored_dir in sorted(IGNORED_DIRS):
        command.extend(["--exclude", ignored_dir])
    return command


def get_config_section(config: dict) -> dict:
    section = config.get("scan", {})
    return section if isinstance(section, dict) else {}


def config_value(config: dict, key: str, default=None):
    section = get_config_section(config)
    if key in section:
        return section[key]
    return config.get(key, default)


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


def get_config_base(config: dict, target_path: Path) -> Path:
    config_base = Path(config.get("_config_path", target_path)).resolve()
    return config_base.parent if config_base.is_file() else config_base


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
        path_value = item.get("path")
        resolved_path = None
        if path_value:
            path_obj = Path(str(path_value))
            resolved_path = str(path_obj.resolve() if path_obj.is_absolute() else (base / path_obj).resolve())
        normalized.append({
            "tool": str(item.get("tool", "")).lower(),
            "rule": str(item.get("rule", "")).lower(),
            "path": str(path_value) if path_value else "",
            "resolved_path": resolved_path,
            "reason": str(item.get("reason", "No reason provided.")),
        })
    return normalized


def suppression_matches(suppression: dict, *, tool: str, rule: str = "", path: str = "") -> bool:
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


def apply_suppressions(scan_dir: Path, suppressions: list[dict]):
    if not suppressions:
        return

    applied = []

    def suppress_item(tool: str, item: dict, *, rule_keys: tuple[str, ...], path_keys: tuple[str, ...]) -> bool:
        rule = next((item.get(key) for key in rule_keys if item.get(key)), "")
        path = next((item.get(key) for key in path_keys if item.get(key)), "")
        for suppression in suppressions:
            if suppression_matches(suppression, tool=tool, rule=str(rule), path=str(path)):
                applied.append({
                    "tool": tool,
                    "rule": rule,
                    "path": path,
                    "reason": suppression["reason"],
                })
                return True
        return False

    ruff_path = scan_dir / "ruff-report.json"
    if ruff_path.exists():
        ruff = json.loads(ruff_path.read_text())
        if isinstance(ruff, list):
            ruff = [
                item for item in ruff
                if not suppress_item("Ruff", item, rule_keys=("code",), path_keys=("filename",))
            ]
            write_json(ruff_path, ruff)

    semgrep_path = scan_dir / "semgrep-report.json"
    if semgrep_path.exists():
        semgrep = json.loads(semgrep_path.read_text())
        if isinstance(semgrep, dict):
            results = semgrep.get("results", [])
            semgrep["results"] = [
                item for item in results
                if not suppress_item("Semgrep", item, rule_keys=("check_id",), path_keys=("path",))
            ]
            write_json(semgrep_path, semgrep)

    yara_path = scan_dir / "yara-report.json"
    if yara_path.exists():
        yara = json.loads(yara_path.read_text())
        if isinstance(yara, list):
            yara = [
                item for item in yara
                if not suppress_item("YARA", item, rule_keys=("rule",), path_keys=("filename",))
            ]
            write_json(yara_path, yara)

    clamav_path = scan_dir / "clamav-report.json"
    if clamav_path.exists():
        clamav = json.loads(clamav_path.read_text())
        if isinstance(clamav, list):
            clamav = [
                item for item in clamav
                if not suppress_item("ClamAV", item, rule_keys=("virus",), path_keys=("filename",))
            ]
            write_json(clamav_path, clamav)

    secrets_path = scan_dir / "secrets-report.json"
    if secrets_path.exists():
        secrets = json.loads(secrets_path.read_text())
        if isinstance(secrets, dict):
            results = secrets.get("results", {})
            for filename, items in list(results.items()):
                results[filename] = [
                    item for item in items
                    if not suppress_item("Secrets", {**item, "filename": filename}, rule_keys=("type",), path_keys=("filename",))
                ]
                if not results[filename]:
                    del results[filename]
            write_json(secrets_path, secrets)

    write_json(scan_dir / "suppressions-report.json", applied)


def write_sarif_report(path: Path, results: list[dict], base_path: Path | None = None):
    severity_to_level = {
        "HIGH": "error",
        "CRITICAL": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    sarif_results = []
    rules = {}

    for tool_result in results or []:
        tool_name = tool_result.get("tool", "Aegis")
        for issue in tool_result.get("examples", []):
            rule_id = str(issue.get("test_id") or issue.get("vulnerability_id") or issue.get("rule") or tool_name)
            message = str(issue.get("issue_text") or issue.get("description") or issue.get("package_name") or "Aegis finding")
            severity = str(issue.get("severity") or "MEDIUM").upper()
            filename = issue.get("filename") or issue.get("path") or "requirements.txt"
            artifact_uri = str(filename)
            if base_path:
                try:
                    artifact_uri = str(Path(artifact_uri).resolve().relative_to(base_path.resolve()))
                except ValueError:
                    artifact_uri = str(filename)
            line = issue.get("line_number") or 1
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message[:120]},
            })
            sarif_results.append({
                "ruleId": rule_id,
                "level": severity_to_level.get(severity, "warning"),
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                        "region": {"startLine": int(line) if str(line).isdigit() else 1},
                    }
                }],
                "properties": {
                    "tool": tool_name,
                    "severity": severity,
                },
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Aegis",
                    "informationUri": "https://github.com/huslenine999/aegis",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    write_json(path, sarif)


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary_path.write_text(f"{json.dumps(data, indent=2)}\n")
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def format_duration(seconds: float) -> str:
    return f"{seconds:.2f}s"


def record_timing(timings: list[dict], name: str, start: float, status: str = "completed"):
    timings.append({
        "name": name,
        "seconds": round(time.perf_counter() - start, 3),
        "status": status,
    })


@contextlib.contextmanager
def timed_step(timings: list[dict], name: str, status: str = "completed"):
    start = time.perf_counter()
    try:
        yield
    finally:
        record_timing(timings, name, start, status)


def print_timing_summary(timings: list[dict]):
    if not timings:
        return
    print("\nScanner timings:")
    for item in timings:
        suffix = f" ({item['status']})" if item.get("status") and item["status"] != "completed" else ""
        print(f"  {item['name']}: {format_duration(item['seconds'])}{suffix}")


def get_package_version() -> str:
    package_path = PROJECT_ROOT / "package.json"
    if package_path.exists():
        try:
            return json.loads(package_path.read_text()).get("version", "unknown")
        except json.JSONDecodeError:
            return "unknown"
    try:
        return importlib.metadata.version("aegis-security-console")
    except importlib.metadata.PackageNotFoundError:
        pass
    return "unknown"


def set_fail_on_env(severities: str):
    severity_set = {
        severity.strip().upper()
        for severity in severities.split(",")
        if severity.strip()
    }
    normalized = ",".join(sorted(severity_set))
    if normalized:
        os.environ["FAIL_ON_RUFF"] = normalized
        os.environ["FAIL_ON_SEMGREP"] = normalized
        os.environ["FAIL_ON_TRIVY"] = normalized
        import policy_engine
        policy_engine.FAIL_ON_RUFF_SEVERITIES = severity_set
        policy_engine.FAIL_ON_SEMGREP_SEVERITIES = severity_set
        policy_engine.FAIL_ON_TRIVY_SEVERITIES = severity_set


def build_scan_summary(target_path: Path, scan_dir: Path, exit_code: int, policy_summary: dict, timings: list[dict] | None = None) -> dict:
    status = {
        EXIT_ALLOWED: "allowed",
        EXIT_BLOCKED: "blocked",
        EXIT_OPERATIONAL_ERROR: "error",
    }.get(exit_code, "error")
    return {
        "target": str(target_path),
        "scan_dir": str(scan_dir),
        "html_report": str(scan_dir / "report.html"),
        "markdown_report": str(scan_dir / "report.md"),
        "manifest": str(scan_dir / "scan-manifest.json"),
        "exit_code": exit_code,
        "status": status,
        "timings": timings or [],
        **policy_summary,
    }


def find_free_host_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


def run_scanner_command(command, *, stdout=None, timeout: int = DEFAULT_TOOL_TIMEOUT, label: str = "Scanner") -> int:
    try:
        result = subprocess.run(
            command,
            stdout=stdout if stdout is not None else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=timeout,
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        print(f"  [{label} Warn] Timed out after {timeout}s; continuing with available results.")
    except FileNotFoundError:
        print(f"  [{label} Warn] Executable not found; skipping.")
    except Exception as e:
        print(f"  [{label} Error] Failed to run scanner: {e}")
    return 1


def log_scanner_event(message: str, level: str = "info"):
    colors = {
        "error": "\033[91m",
        "match": "\033[93m",
        "muted": "\033[90m",
    }
    color = colors.get(level, "")
    reset = "\033[0m" if color else ""
    print(f"  {color}{message}{reset}")

def run_dast_scan(target_url: str = None):
    findings = []
    test_cases = [
        {
            "vuln_type": "SQL Injection",
            "route": "/user",
            "method": "GET",
            "params": {"name": "admin' OR '1'='1"},
            "payload": "admin' OR '1'='1",
            "description": "Active SQL injection vulnerability in user lookup endpoint."
        },
        {
            "vuln_type": "Remote Code Execution",
            "route": "/ping",
            "method": "GET",
            "params": {"host": "127.0.0.1; cat /etc/passwd"},
            "payload": "127.0.0.1; cat /etc/passwd",
            "description": "Command injection vulnerability in ping routing."
        },
        {
            "vuln_type": "Unsafe Eval Injection",
            "route": "/calculate",
            "method": "GET",
            "params": {"expr": "__import__('os').system('id')"},
            "payload": "__import__('os').system('id')",
            "description": "Arbitrary Python execution via unsafe eval expression injection."
        },
        {
            "vuln_type": "Path Traversal (LFI)",
            "route": "/download",
            "method": "GET",
            "params": {"file": "../requirements.txt"},
            "payload": "../requirements.txt",
            "description": "Local File Inclusion / Path Traversal vulnerability."
        },
        {
            "vuln_type": "Cross-Site Scripting (XSS)",
            "route": "/xss",
            "method": "GET",
            "params": {"msg": "<script>alert('XSS')</script>"},
            "payload": "<script>alert('XSS')</script>",
            "description": "Reflected Cross-Site Scripting vulnerability."
        },
        {
            "vuln_type": "Server-Side Request Forgery (SSRF)",
            "route": "/ssrf",
            "method": "GET",
            "params": {"url": "http://169.254.169.254/latest/meta-data/"},
            "payload": "http://169.254.169.254/latest/meta-data/",
            "description": "Server-Side Request Forgery vulnerability exposing cloud metadata."
        }
    ]

    import requests
    if target_url:
        for tc in test_cases:
            url = f"{target_url}{tc['route']}"
            print(f"  [DAST] Scanning route: {tc['route']} with payload: {tc['payload']}")
            try:
                res = requests.get(url, params=tc["params"], timeout=3)
                status_code = res.status_code
            except Exception:
                status_code = 500
            
            status = "MITIGATED" if status_code == 403 else "EXPOSED"
            color = "\033[92m" if status_code == 403 else "\033[91m"
            print(f"  [DAST] Result for {tc['vuln_type']}: {color}{status}\033[0m (HTTP {status_code})")
            
            findings.append({
                "vuln_type": tc["vuln_type"],
                "route": tc["route"],
                "payload": tc["payload"],
                "description": tc["description"],
                "status": status,
                "response_code": status_code
            })
    return findings

def format_cell(text: str, width: int, align: str = "left", color: str = "") -> str:
    if align == "left":
        padded = text.ljust(width)
    elif align == "center":
        padded = text.center(width)
    elif align == "right":
        padded = text.rjust(width)
    else:
        padded = text.ljust(width)
        
    if color:
        return f"{color}{padded}\033[0m"
    return padded

def print_ascii_report(results: list, final_status: str, reason: str, exploitability_score: float):
    cyan = "\033[96m"
    reset = "\033[0m"
    bold = "\033[1m"
    gray = "\033[90m"
    yellow = "\033[93m"
    green = "\033[92m"
    red = "\033[91m"
    
    # ASCII Art Header
    print("\n")
    print(f"  {cyan}╔══════════════════════════════════════════════════════════════════════════╗{reset}")
    print(f"  {cyan}║{reset}   {cyan}█████╗ ███████╗ ██████╗ ██╗███████╗{reset}                                    {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██╔══██╗██╔════╝██╔════╝ ██║██╔════╝{reset}   {bold}A E G I S   S E C U R I T Y{reset}      {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}███████║█████╗  ██║  ███╗██║███████╗{reset}   {bold}S E C U R E   G A T E W A Y{reset}      {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██╔══██║██╔══╝  ██║   ██║██║╚════██║{reset}   {gray}SHIELD ACTIVE v2.0{reset}                {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}██║  ██║███████╗╚██████╔╝██║███████║{reset}                                     {cyan}║{reset}")
    print(f"  {cyan}║{reset}  {cyan}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝{reset}                                     {cyan}║{reset}")
    print(f"  {cyan}╚══════════════════════════════════════════════════════════════════════════╝{reset}")
    
    # Table Header
    print(f"  {gray}┌──────────────────────────────┬──────────┬──────────────┬─────────────────┐{reset}")
    h1 = format_cell("SCANNER SUITE", 30, "left", "\033[96m\033[1m")
    h2 = format_cell("STATUS", 10, "center", "\033[96m\033[1m")
    h3 = format_cell("TOTAL ISSUES", 14, "right", "\033[96m\033[1m")
    h4 = format_cell("BLOCKING ISSUES", 17, "right", "\033[96m\033[1m")
    print(f"  {gray}│{reset}{h1}{gray}│{reset}{h2}{gray}│{reset}{h3}{gray}│{reset}{h4}{gray}│{reset}")
    print(f"  {gray}├──────────────────────────────┼──────────┼──────────────┼─────────────────┤{reset}")
    
    # Table Rows
    for r in results:
        tool_name = r["tool"]
        status = r["status"]
        total = str(r["total_issues"])
        blocking = str(r["blocking_issues"])
        
        if status == "PASS":
            status_text = "✔ PASS"
            status_color = green
        elif status == "FAIL":
            status_text = "✘ FAIL"
            status_color = red
        elif status == "MISSING":
            status_text = "⚠ MISSING"
            status_color = yellow
        else:
            status_text = status
            status_color = reset
            
        t_cell = format_cell(" " + tool_name, 30, "left")
        s_cell = format_cell(status_text, 10, "center", status_color)
        tot_cell = format_cell(total + " ", 14, "right")
        blk_cell = format_cell(blocking + " ", 17, "right", status_color if status == "FAIL" else "")
        print(f"  {gray}│{reset}{t_cell}{gray}│{reset}{s_cell}{gray}│{reset}{tot_cell}{gray}│{reset}{blk_cell}{gray}│{reset}")
        
    print(f"  {gray}└──────────────────────────────┴──────────┴──────────────┴─────────────────┘{reset}")
    
    # Exploitability risk gauge panel card
    print(f"  {cyan}╔══════════════════════════════════════════════════════════════════════════╗{reset}")
    
    # Draw exploitability score bar (gauge width = 40 characters)
    filled_width = int(exploitability_score / 100.0 * 40.0)
    empty_width = 40 - filled_width
    gauge_str = "█" * filled_width + "░" * empty_width
    
    if exploitability_score >= 80.0:
        gauge_color = red
    elif exploitability_score >= 40.0:
        gauge_color = yellow
    else:
        gauge_color = green
        
    visible_gauge = f"  EXPLOITABILITY RISK: [{gauge_str}] {exploitability_score}%"
    padded_gauge = visible_gauge.ljust(74)
    color_gauge = padded_gauge.replace(gauge_str, gauge_color + gauge_str + reset)
    print(f"  {cyan}║{reset}{color_gauge}{cyan}║{reset}")
    
    print(f"  {cyan}║{reset}{' ' * 74}{cyan}║{reset}")
    
    if final_status == "ALLOWED":
        verdict_label = "[✔] DEPLOYMENT ALLOWED"
        verdict_color = green + bold
    elif final_status == "ERROR":
        verdict_label = "[!] SCAN INCOMPLETE"
        verdict_color = yellow + bold
    else:
        verdict_label = "[✘] DEPLOYMENT BLOCKED"
        verdict_color = red + bold
    
    visible_verdict = f"  VERDICT: {verdict_label}"
    padded_verdict = visible_verdict.ljust(74)
    color_verdict = padded_verdict.replace(verdict_label, verdict_color + verdict_label + reset)
    print(f"  {cyan}║{reset}{color_verdict}{cyan}║{reset}")
    
    visible_reason = f"  REASON:  {reason}"
    if len(visible_reason) > 72:
        visible_reason = visible_reason[:69] + "..."
    padded_reason = visible_reason.ljust(74)
    print(f"  {cyan}║{reset}{padded_reason}{cyan}║{reset}")
    
    print(f"  {cyan}╚══════════════════════════════════════════════════════════════════════════╝{reset}")

def execute_scan(
    target_path_str: str,
    *,
    use_docker: bool = True,
    tool_timeout: int | None = DEFAULT_TOOL_TIMEOUT,
    output_dir: str = None,
    json_output: bool = False,
    quiet: bool = False,
    fail_on: str = None,
    fast: bool = False,
    config_path: str = None,
    sarif: str | bool | None = None,
    strict: bool | None = None,
    return_summary: bool = False,
):
    timings = []
    total_start = time.perf_counter()
    started_at = utc_timestamp()
    tool_statuses = []

    def mark_tool(name: str, status: str, *, detail: str | None = None, return_code: int | None = None):
        record = next((item for item in tool_statuses if item["name"] == name), None)
        if record is None:
            record = {"name": name}
            tool_statuses.append(record)
        record["status"] = status
        if detail:
            record["detail"] = detail
        if return_code is not None:
            record["return_code"] = return_code

    target_path = Path(target_path_str).resolve()
    if not target_path.exists():
        print(f"❌ Error: Path '{target_path}' does not exist.")
        if return_summary:
            return {
                "target": str(target_path),
                "exit_code": EXIT_OPERATIONAL_ERROR,
                "status": "error",
                "error": "target_not_found",
            }
        return EXIT_OPERATIONAL_ERROR

    if config_path and not Path(config_path).expanduser().is_file():
        raise ValueError(f"Config file does not exist: {Path(config_path).expanduser()}")
    config = load_config(target_path, config_path)
    if "scan" in config and not isinstance(config["scan"], dict):
        raise ValueError("Aegis config key 'scan' must be a mapping.")
    if config:
        if fail_on is None:
            fail_on = config_value(config, "fail_on")
        if output_dir is None:
            output_dir = config_value(config, "output_dir")
        if sarif is None:
            sarif = config_value(config, "sarif", None)
        if tool_timeout is None:
            tool_timeout = int(config_value(config, "timeout", DEFAULT_TOOL_TIMEOUT))
        if strict is None:
            strict = config_bool(get_config_section(config), "strict", config_bool(config, "strict", False))
        fast = fast or config_bool(get_config_section(config), "fast", config_bool(config, "fast", False))
        use_docker = use_docker and not config_bool(get_config_section(config), "no_docker", config_bool(config, "no_docker", False))

    if tool_timeout is None:
        tool_timeout = DEFAULT_TOOL_TIMEOUT
    if tool_timeout <= 0:
        raise ValueError("--timeout must be greater than zero.")
    strict = bool(strict)
    fail_on = validate_fail_on(fail_on)
    if fail_on:
        set_fail_on_env(str(fail_on))
    if fast:
        use_docker = False

    excluded_paths = resolve_exclude_paths(config, target_path)
    suppressions = normalize_suppressions(config, target_path)

    print(f"🛡️  Aegis CLI Scanner: Auditing target path: {target_path}")

    # Set up local scans directory
    dependency_manifests = discover_dependency_manifests(target_path)
    requirements_manifest = first_requirements_manifest(dependency_manifests)
    req_file = requirements_manifest.path if requirements_manifest else None

    if output_dir:
        scan_dir = Path(output_dir).expanduser().resolve()
    elif target_path.is_dir():
        scan_dir = target_path / ".aegis" / "scans"
    else:
        scan_dir = target_path.parent / ".aegis" / "scans"

    scan_dir.mkdir(parents=True, exist_ok=True)

    # Initialize placeholder reports to satisfy policy engine requirements
    placeholder_reports = {
        "ruff-report.json": [],
        "safety-report.json": [],
        "trivy-report.json": {"Results": []},
        "secrets-report.json": {"results": {}},
        "yara-report.json": [],
        "semgrep-report.json": {"results": []},
        "clamav-report.json": [],
        "zap-report.json": [],
        "osv-report.json": [],
    }
    for filename, default_data in placeholder_reports.items():
        write_json(scan_dir / filename, default_data)

    # 1. Dependency Analysis (Safety / OSV)
    if fast:
        print(f"ℹ️  [Fast Mode] Skipping slower checks: {FAST_MODE_SKIPPED_SCANNERS}.")
        record_timing(timings, "Safety/OSV", time.perf_counter(), "skipped")
        mark_tool("Safety", "skipped", detail="fast mode")
        mark_tool("OSV", "skipped", detail="fast mode")
    elif dependency_manifests:
        with timed_step(timings, "Safety/OSV"):
            manifest_names = ", ".join(sorted({manifest.kind for manifest in dependency_manifests}))
            print(f"🔍 [SCA] Dependency manifest(s) detected: {manifest_names}. Running available Safety and OSV audits...")
            
            # Safety Scan
            safety_report_path = scan_dir / "safety-report.json"
            if req_file:
                safety_cmd = [sys.executable, "-m", "safety", "check", "-r", str(req_file), "--save-json", str(safety_report_path)]
                safety_report_path.unlink(missing_ok=True)
                safety_return_code = run_scanner_command(safety_cmd, timeout=tool_timeout, label="Safety")
                safety_report = read_json(safety_report_path)
                if isinstance(safety_report, (dict, list)):
                    mark_tool("Safety", "completed", return_code=safety_return_code)
                else:
                    write_json(safety_report_path, [])
                    mark_tool(
                        "Safety",
                        "failed",
                        detail="scanner did not produce a valid JSON report",
                        return_code=safety_return_code,
                    )
            else:
                write_json(safety_report_path, [])
                mark_tool("Safety", "skipped", detail="no requirements.txt manifest")
            
            # OSV Scan
            osv_report_path = scan_dir / "osv-report.json"
            try:
                osv_findings = query_osv_vulnerabilities(dependency_manifests, raise_on_error=strict)
                write_json(osv_report_path, osv_findings)
                print("  [SCA] OSV API checks completed.")
                mark_tool("OSV", "completed")
            except Exception as e:
                print(f"  [SCA Warn] OSV query failed: {e}")
                mark_tool("OSV", "failed", detail=str(e))
    else:
        print("ℹ️  [SCA] No supported dependency manifest found, skipping dependency scan.")
        record_timing(timings, "Safety/OSV", time.perf_counter(), "skipped")
        mark_tool("Safety", "skipped", detail="dependency manifest not found")
        mark_tool("OSV", "skipped", detail="dependency manifest not found")

    # 2. Python SAST (Ruff)
    with timed_step(timings, "Ruff"):
        print("🔍 [SAST] Running Ruff (SAST) code security audits...")
        ruff_report_path = scan_dir / "ruff-report.json"
        ruff_cmd = [sys.executable, "-m", "ruff", "check", "--select", "S", "--output-format", "json", "-o", str(ruff_report_path), str(target_path)]
        ruff_excludes = sorted(IGNORED_DIRS | excluded_paths)
        ruff_cmd.extend(["--exclude", ",".join(ruff_excludes)])
        ruff_report_path.unlink(missing_ok=True)
        ruff_return_code = run_scanner_command(ruff_cmd, timeout=tool_timeout, label="Ruff")
        ruff_report = read_json(ruff_report_path)
        if ruff_return_code in {0, 1} and isinstance(ruff_report, list):
            mark_tool("Ruff", "completed", return_code=ruff_return_code)
        else:
            write_json(ruff_report_path, [])
            mark_tool(
                "Ruff",
                "failed",
                detail="scanner did not produce a valid report",
                return_code=ruff_return_code,
            )


    # 3. Python SAST (Semgrep)
    print("🔍 [SAST] Running Semgrep rule-based scans...")
    semgrep_report_path = scan_dir / "semgrep-report.json"
    rules_dir = PROJECT_ROOT / "rules"
    rules_dir.mkdir(exist_ok=True)
    semgrep_rules_path = rules_dir / "semgrep_rules.yaml"
    if not semgrep_rules_path.exists():
        write_semgrep_rules(semgrep_rules_path)

    # Find semgrep binary in virtual env or system
    semgrep_bin = shutil.which("semgrep")
    if fast:
        print("ℹ️  [SAST:Semgrep] Fast mode enabled, skipping Semgrep rule check.")
        record_timing(timings, "Semgrep", time.perf_counter(), "skipped")
        mark_tool("Semgrep", "skipped", detail="fast mode")
    elif semgrep_bin:
        with timed_step(timings, "Semgrep"):
            configure_semgrep_environment()
            semgrep_cmd = [
                semgrep_bin,
                "scan",
                "--metrics",
                "off",
                "--disable-version-check",
                "--config",
                str(semgrep_rules_path),
                "--json",
            ]
            add_semgrep_excludes(semgrep_cmd)
            for excluded_path in sorted(excluded_paths):
                semgrep_cmd.extend(["--exclude", excluded_path])
            semgrep_cmd.extend(["-o", str(semgrep_report_path), str(target_path)])
            semgrep_report_path.unlink(missing_ok=True)
            semgrep_return_code = run_scanner_command(semgrep_cmd, timeout=tool_timeout, label="Semgrep")
            semgrep_report = read_json(semgrep_report_path)
            if semgrep_return_code == 0 and isinstance(semgrep_report, dict):
                mark_tool("Semgrep", "completed", return_code=semgrep_return_code)
            else:
                write_json(semgrep_report_path, {"results": []})
                mark_tool(
                    "Semgrep",
                    "failed",
                    detail="scanner did not produce a valid report",
                    return_code=semgrep_return_code,
                )
    else:
        print("  [SAST Warn] semgrep executable not found, skipping rule check.")
        record_timing(timings, "Semgrep", time.perf_counter(), "skipped")
        mark_tool("Semgrep", "failed", detail="executable not found")

    # 4. Secret Auditing (detect-secrets)
    print("🔍 [Secrets] Scanning codebase for hardcoded keys and credentials...")
    secrets_report_path = scan_dir / "secrets-report.json"
    secrets_excludes = [
        EXCLUDE_FILES_PATTERN,
        *[re.escape(path) for path in sorted(excluded_paths)],
    ]
    scan_root = target_path if target_path.is_dir() else target_path.parent
    try:
        output_relative_path = scan_dir.relative_to(scan_root).as_posix()
        secrets_excludes.append(re.escape(output_relative_path))
    except ValueError:
        pass
    secrets_cmd = [
        sys.executable,
        "-m",
        "detect_secrets",
        "scan",
        "--all-files",
        "--exclude-files",
        "|".join(secrets_excludes),
        "--no-verify",
        str(target_path),
    ]
    with timed_step(timings, "Secrets"):
        secrets_raw_path = secrets_report_path.with_suffix(".raw.json")
        try:
            with open(secrets_raw_path, "w") as f:
                secrets_return_code = run_scanner_command(
                    secrets_cmd,
                    stdout=f,
                    timeout=tool_timeout,
                    label="Secrets",
                )
            secrets_report = read_json(secrets_raw_path)
            if secrets_return_code == 0 and isinstance(secrets_report, dict):
                write_json(secrets_report_path, secrets_report)
                mark_tool("Secrets", "completed", return_code=secrets_return_code)
            else:
                write_json(secrets_report_path, {"results": {}})
                mark_tool(
                    "Secrets",
                    "failed",
                    detail="scanner did not produce a valid report",
                    return_code=secrets_return_code,
                )
        except Exception as e:
            print(f"  [Secrets Error] Failed to run detect-secrets: {e}")
            write_json(secrets_report_path, {"results": {}})
            mark_tool("Secrets", "failed", detail=str(e))
        finally:
            secrets_raw_path.unlink(missing_ok=True)

    # 5. YARA Pattern Audits
    with timed_step(timings, "YARA"):
        print("🔍 [YARA] Auditing code logic for webshells and suspicious execution patterns...")
        yara_findings = shared_run_yara_scan(target_path, ignored_paths=excluded_paths, log=log_scanner_event)
        write_json(scan_dir / "yara-report.json", yara_findings)
        mark_tool("YARA", "completed")

    # 6. ClamAV Malware Scan
    if fast:
        print("ℹ️  [ClamAV] Fast mode enabled, skipping ClamAV malware check.")
        record_timing(timings, "ClamAV", time.perf_counter(), "skipped")
        mark_tool("ClamAV", "skipped", detail="fast mode")
    else:
        with timed_step(timings, "ClamAV"):
            print("🔍 [ClamAV] Searching files for virus signatures...")
            clamav_findings = shared_run_clamav_scan(target_path, ignored_paths=excluded_paths, timeout=tool_timeout, log=log_scanner_event)
            write_json(scan_dir / "clamav-report.json", clamav_findings)
            mark_tool("ClamAV", "completed")

    # 7. Sandbox Execution (Trivy & DAST) via Docker
    has_python = False
    if target_path.is_dir():
        for root, dirs, files in os.walk(target_path):
            if should_skip_path(Path(root)):
                continue
            if any(file.endswith(".py") for file in files):
                has_python = True
                break
    else:
        if target_path.suffix.lower() == ".py":
            has_python = True

    if fast:
        print("ℹ️  [Docker Sandbox] Fast mode enabled, skipping Docker, Trivy, and DAST checks.")
        record_timing(timings, "Docker/Trivy/DAST", time.perf_counter(), "skipped")
        mark_tool("Docker Sandbox", "skipped", detail="fast mode")
        mark_tool("Trivy", "skipped", detail="fast mode")
        mark_tool("DAST", "skipped", detail="fast mode")
    elif use_docker and is_docker_available() and has_python:
        with timed_step(timings, "Docker/Trivy/DAST"):
            print("🔍 [Docker Sandbox] Docker daemon detected. Building sandbox server and executing Trivy and DAST scans...")
            sandbox_uuid = uuid.uuid4().hex
            sandbox_image = f"aegis-sandbox-{sandbox_uuid}"
            sandbox_container = f"aegis-sandbox-container-{sandbox_uuid}"
            sandbox_temp_dir = scan_dir / "sandbox" / sandbox_uuid
            
            try:
                host_port = find_free_host_port()
                    
                container_port = scaffold_sandbox_context(target_path, sandbox_temp_dir)
                target_url = f"http://127.0.0.1:{host_port}"
                waf_enabled = os.environ.get("WAF_ENABLED", "false").lower() == "true"

                if not build_sandbox_image(sandbox_temp_dir, sandbox_image):
                    raise RuntimeError("failed to build sandbox image")

                if not run_sandbox_container(sandbox_image, sandbox_container, host_port, container_port, waf_enabled):
                    raise RuntimeError("failed to start sandbox container")

                if not wait_for_container(target_url, timeout=6.0):
                    raise RuntimeError("sandbox container did not become healthy")
                mark_tool("Docker Sandbox", "completed")

                # 7a. Trivy layer audits
                trivy_report_path = scan_dir / "trivy-report.json"
                print("  [Trivy] Inspecting image layer packages for CVEs...")
                try:
                    run_trivy_scan(sandbox_image, trivy_report_path)
                    mark_tool("Trivy", "completed")
                except Exception as e:
                    print(f"  [Trivy Error] Image scan failed: {e}")
                    mark_tool("Trivy", "failed", detail=str(e))

                # 7b. Aegis DAST Probe active scanning
                zap_report_path = scan_dir / "zap-report.json"
                print("  [DAST] Running active crawler against endpoints...")
                zap_findings = run_dast_scan(target_url)
                write_json(zap_report_path, zap_findings)
                mark_tool("DAST", "completed")

            except Exception as e:
                print(f"  \033[91m[Sandbox Error] Docker execution pipeline encountered an error: {e}\033[0m")
                mark_tool("Docker Sandbox", "failed", detail=str(e))
                if not any(item["name"] == "Trivy" for item in tool_statuses):
                    mark_tool("Trivy", "skipped", detail="sandbox unavailable")
                if not any(item["name"] == "DAST" for item in tool_statuses):
                    mark_tool("DAST", "skipped", detail="sandbox unavailable")
            finally:
                print("  [Docker Sandbox] Cleaning up sandbox containers...")
                try:
                    stop_and_cleanup_sandbox(sandbox_container, sandbox_image)
                except Exception:
                    pass
                if sandbox_temp_dir.exists():
                    shutil.rmtree(sandbox_temp_dir, ignore_errors=True)
    else:
        print("ℹ️  [Docker Sandbox] Docker is disabled, unavailable, or no Python target found. Skipping Trivy & DAST scans.")
        record_timing(timings, "Docker/Trivy/DAST", time.perf_counter(), "skipped")
        if use_docker and has_python:
            mark_tool("Docker Sandbox", "failed", detail="Docker is unavailable")
            mark_tool("Trivy", "skipped", detail="Docker is unavailable")
            mark_tool("DAST", "skipped", detail="Docker is unavailable")
        else:
            reason = "disabled" if not use_docker else "no Python target found"
            mark_tool("Docker Sandbox", "skipped", detail=reason)
            mark_tool("Trivy", "skipped", detail=reason)
            mark_tool("DAST", "skipped", detail=reason)

    # 8. Run Policy Engine
    print("\nEvaluating all reports against Aegis Security Gate rules...")
    html_report = scan_dir / "report.html"
    md_report = scan_dir / "report.md"
    policy_summary = {}
    apply_suppressions(scan_dir, suppressions)

    def capture_policy_summary(results, final_status, reason, exploitability_score):
        policy_summary.update({
            "policy_status": final_status,
            "reason": reason,
            "exploitability_score": exploitability_score,
            "results": results,
        })
        if not json_output and not quiet:
            print_ascii_report(results, final_status, reason, exploitability_score)
    
    # Run the policy engine
    pre_policy_failures = [item["name"] for item in tool_statuses if item["status"] == "failed"]
    with timed_step(timings, "Policy Engine"):
        policy_exit_code = run_policy_engine(
            scan_dir=scan_dir,
            html_path=html_report,
            md_path=md_report,
            req_path=req_file,
            dependency_manifests=dependency_manifests,
            reporter_callback=capture_policy_summary,
            operational_failures=pre_policy_failures if strict else None,
            tool_states={item["name"]: item["status"] for item in tool_statuses},
        )
    record_timing(timings, "Total", total_start)
    mark_tool("Policy Engine", "completed", return_code=policy_exit_code)

    sarif_path = None
    if sarif:
        if isinstance(sarif, str) and sarif not in {"1", "true", "yes", "on"}:
            candidate = Path(sarif)
            sarif_path = candidate if candidate.is_absolute() else scan_dir / candidate
        else:
            sarif_path = scan_dir / "aegis.sarif"
        sarif_base = target_path if target_path.is_dir() else target_path.parent
        write_sarif_report(sarif_path, policy_summary.get("results", []), base_path=sarif_base)
        policy_summary["sarif_report"] = str(sarif_path)

    failed_tools = [item["name"] for item in tool_statuses if item["status"] == "failed"]
    exit_code = policy_exit_code
    if strict and failed_tools:
        exit_code = EXIT_OPERATIONAL_ERROR
        policy_summary["operational_failures"] = failed_tools

    manifest = {
        "schema_version": 1,
        "aegis_version": get_package_version(),
        "target": str(target_path),
        "started_at": started_at,
        "completed_at": utc_timestamp(),
        "strict": strict,
        "fast": fast,
        "docker_requested": use_docker,
        "policy_exit_code": policy_exit_code,
        "exit_code": exit_code,
        "status": {
            EXIT_ALLOWED: "allowed",
            EXIT_BLOCKED: "blocked",
            EXIT_OPERATIONAL_ERROR: "error",
        }.get(exit_code, "error"),
        "tools": tool_statuses,
    }
    write_json(scan_dir / "scan-manifest.json", manifest)
    policy_summary["tools"] = tool_statuses

    print(f"\nScan complete. Dossier report available at: {html_report}")
    if not json_output and not quiet:
        print_timing_summary(timings)
    if return_summary:
        return build_scan_summary(target_path, scan_dir, exit_code, policy_summary, timings)
    return exit_code


def run_doctor(json_output: bool = False) -> int:
    checks = []

    def add_check(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    add_check("python", True, sys.version.split()[0])
    add_check("project_root", PROJECT_ROOT.exists(), str(PROJECT_ROOT))
    add_check("ruff", True, "python module available")
    try:
        importlib.metadata.version("ruff")
    except importlib.metadata.PackageNotFoundError:
        checks[-1] = {"name": "ruff", "ok": False, "detail": "python module missing"}

    semgrep_bin = shutil.which("semgrep")
    add_check("semgrep", semgrep_bin is not None, semgrep_bin or "not found")
    trivy_bin = shutil.which("trivy")
    add_check("trivy", trivy_bin is not None, trivy_bin or "not found")
    add_check("docker", is_docker_available(), "available" if is_docker_available() else "unavailable")

    ok = all(check["ok"] for check in checks if check["name"] in {"python", "project_root", "ruff"})
    payload = {"status": "ok" if ok else "degraded", "checks": checks}

    if json_output:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Aegis doctor: {payload['status']}")
        for check in checks:
            marker = "OK" if check["ok"] else "WARN"
            print(f"  [{marker}] {check['name']}: {check['detail']}")
    return 0 if ok else 1


def find_report_file(report_dir: str = None, *, markdown: bool = False) -> Path | None:
    filename = "report.md" if markdown else "report.html"
    if report_dir:
        candidate = Path(report_dir).expanduser().resolve() / filename
        return candidate if candidate.exists() else None
    candidates = [
        Path.cwd() / DEFAULT_SCAN_DIR / filename,
        PROJECT_ROOT / DEFAULT_SCAN_DIR / filename,
        PROJECT_ROOT / "scans" / filename,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def open_report_file(path: Path) -> int:
    if sys.platform == "darwin":
        command = ["open", str(path)]
    elif os.name == "nt":
        command = ["cmd", "/c", "start", "", str(path)]
    else:
        command = ["xdg-open", str(path)]
    try:
        return subprocess.run(command, check=False).returncode
    except FileNotFoundError:
        return 1


def run_report(report_dir: str = None, *, markdown: bool = False, open_report: bool = False, path_only: bool = False) -> int:
    report_path = find_report_file(report_dir, markdown=markdown)
    if not report_path:
        searched = Path(report_dir).expanduser().resolve() if report_dir else Path.cwd() / DEFAULT_SCAN_DIR
        print(f"No Aegis report found. Run `aegis scan .` first or pass --dir. Checked: {searched}")
        return 1

    if path_only:
        print(report_path)
    else:
        print(f"Aegis report: {report_path}")

    if open_report:
        result = open_report_file(report_path)
        if result != 0:
            print(f"Failed to open report automatically: {report_path}")
        return result
    return 0


def create_demo_target(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "app.py").write_text(
        "from flask import Flask, request\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.get('/calculate')\n"
        "def calculate():\n"
        "    return str(eval(request.args.get('expr', '1+1')))\n"
        "\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'status': 'ok'}\n"
    )
    (target_dir / "requirements.txt").write_text("Flask==3.1.3\n")
    (target_dir / "README.md").write_text(
        "# Aegis demo target\n\n"
        "This tiny app intentionally includes an unsafe `eval` route so Aegis can show a blocking finding quickly.\n"
    )


def run_demo(*, open_report: bool = False, output_dir: str | None = None) -> int:
    demo_root = Path.cwd() / ".aegis"
    target_dir = demo_root / "demo-target"
    report_dir = Path(output_dir).expanduser().resolve() if output_dir else demo_root / "demo-report"
    create_demo_target(target_dir)

    print(f"Created demo target: {target_dir}")
    print("Running a quick local scan with Docker-dependent checks disabled...")
    try:
        summary = execute_scan(
            str(target_dir),
            use_docker=False,
            output_dir=str(report_dir),
            fast=True,
            quiet=True,
            return_summary=True,
        )
    except Exception as exc:
        print(f"Aegis demo failed: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR

    status = summary.get("status", "unknown")
    report_path = Path(summary.get("html_report", report_dir / "report.html"))
    markdown_path = Path(summary.get("markdown_report", report_dir / "report.md"))
    print(f"Demo verdict: {status.upper()}")
    print(f"HTML report: {report_path}")
    print(f"Markdown report: {markdown_path}")
    print("The demo target intentionally contains an unsafe eval route, so a blocked verdict is expected.")

    if open_report:
        result = open_report_file(report_path)
        if result != 0:
            print(f"Failed to open report automatically: {report_path}", file=sys.stderr)
            return result
    return 0


def _local_environment_values() -> dict[str, str]:
    return cli_stack.local_environment_values()


def _read_environment_file(path: Path) -> dict[str, str]:
    return cli_stack.read_environment_file(path)


def _write_environment_file(path: Path, values: dict[str, str]) -> None:
    cli_stack.write_environment_file(path, values)


def _docker_compose_command(env_file: Path, *arguments: str) -> list[str]:
    return cli_stack.docker_compose_command(PROJECT_ROOT, env_file, *arguments)


def _port_is_available(port: int) -> bool:
    return cli_stack.port_is_available(port)


def _wait_for_dashboard(url: str, timeout: int = 180) -> bool:
    return cli_stack.wait_for_dashboard(url, timeout)


def run_start(*, no_open: bool = False, foreground: bool = False, regenerate_secrets: bool = False) -> int:
    return cli_stack.run_start(
        project_root=PROJECT_ROOT,
        local_env_file=LOCAL_ENV_FILE,
        subprocess_module=subprocess,
        shutil_module=shutil,
        webbrowser_module=webbrowser,
        no_open=no_open,
        foreground=foreground,
        regenerate_secrets=regenerate_secrets,
        is_port_available=_port_is_available,
        wait_for_ready=_wait_for_dashboard,
    )


def _require_local_stack() -> bool:
    return cli_stack.require_local_stack(local_env_file=LOCAL_ENV_FILE, shutil_module=shutil)


def run_stop() -> int:
    return cli_stack.run_stop(
        project_root=PROJECT_ROOT,
        local_env_file=LOCAL_ENV_FILE,
        subprocess_module=subprocess,
        shutil_module=shutil,
    )


def run_stack_logs(*, follow: bool = False) -> int:
    return cli_stack.run_stack_logs(
        project_root=PROJECT_ROOT,
        local_env_file=LOCAL_ENV_FILE,
        subprocess_module=subprocess,
        shutil_module=shutil,
        follow=follow,
    )


def run_upgrade(*, no_start: bool = False) -> int:
    return cli_stack.run_upgrade(
        project_root=PROJECT_ROOT,
        local_env_file=LOCAL_ENV_FILE,
        subprocess_module=subprocess,
        shutil_module=shutil,
        webbrowser_module=webbrowser,
        run_start_callback=run_start,
        no_start=no_start,
    )


def run_backup(output: str | None = None) -> int:
    return cli_stack.run_backup(
        project_root=PROJECT_ROOT,
        local_env_file=LOCAL_ENV_FILE,
        subprocess_module=subprocess,
        shutil_module=shutil,
        package_version=get_package_version(),
        output=output,
    )


def run_restore(archive_path: str, *, confirmed: bool = False) -> int:
    return cli_stack.run_restore(
        archive_path,
        project_root=PROJECT_ROOT,
        local_env_file=LOCAL_ENV_FILE,
        subprocess_module=subprocess,
        shutil_module=shutil,
        confirmed=confirmed,
    )

def install_hook():
    git_dir = Path(".git")
    if not git_dir.exists() or not git_dir.is_dir():
        print("❌ Error: Not a Git repository (no .git directory found).")
        return 1
        
    hook_dir = git_dir / "hooks"
    hook_dir.mkdir(exist_ok=True)
    
    pre_push_path = hook_dir / "pre-push"
    
    # Resolve the absolute path to Aegis executable
    aegis_bin_abs = PROJECT_ROOT / "bin" / "aegis"
    
    hook_content = f"""#!/bin/bash
# Aegis Security Gate Pre-Push Hook
echo "🛡️ Running Aegis pre-push security scans..."

# Get the directory of the repository
REPO_DIR="$(git rev-parse --show-toplevel)"

# Run Aegis scan
if [ -f "{aegis_bin_abs}" ]; then
  "{aegis_bin_abs}" scan "$REPO_DIR" --fast
else
  aegis scan "$REPO_DIR" --fast
fi
RESULT=$?

if [ $RESULT -ne 0 ]; then
  echo "❌ DEPLOYMENT BLOCKED: Aegis security scans failed."
  exit 1
fi

echo "✅ Aegis security scans passed. Proceeding with push."
exit 0
"""
    
    pre_push_path.write_text(hook_content)
    os.chmod(pre_push_path, 0o755)
    print("✅ Aegis Git pre-push hook installed successfully at .git/hooks/pre-push")
    return 0

def uninstall_hook():
    pre_push_path = Path(".git/hooks/pre-push")
    if pre_push_path.exists():
        pre_push_path.unlink()
        print("✅ Aegis Git pre-push hook uninstalled successfully.")
    else:
        print("ℹ️ Aegis Git pre-push hook is not currently installed.")
    return 0

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Aegis DevSecOps Console CLI Scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run in-process security audit scan")
    scan_parser.add_argument("path", nargs="?", default=".", help="Target path to scan (defaults to current directory)")
    scan_parser.add_argument("--no-docker", action="store_true", help="Skip Docker sandbox, Trivy, and DAST scans")
    scan_parser.add_argument("--timeout", type=int, default=None, help="Per-tool timeout in seconds")
    scan_parser.add_argument("--output", help="Directory for generated scan reports")
    scan_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON summary to stdout")
    scan_parser.add_argument("--quiet", action="store_true", help="Suppress scan progress output")
    scan_parser.add_argument("--fail-on", help="Comma-separated severities that should block, e.g. high,critical")
    scan_parser.add_argument("--config", help="Path to aegis.yml config file")
    scan_parser.add_argument("--sarif", nargs="?", const="aegis.sarif", help="Write SARIF output, optionally to the given filename")
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        default=None,
        help="Fail with exit code 2 when a requested scanner cannot complete reliably",
    )
    scan_parser.add_argument(
        "--fast",
        action="store_true",
        help=f"Run a quicker local scan by skipping {FAST_MODE_SKIPPED_SCANNERS}",
    )

    subparsers.add_parser("install-hook", help="Install Aegis Git pre-push hook")
    subparsers.add_parser("uninstall-hook", help="Uninstall Aegis Git pre-push hook")
    start_parser = subparsers.add_parser("start", help="Start the complete local Aegis stack")
    start_parser.add_argument("--no-open", action="store_true", help="Do not open the setup page")
    start_parser.add_argument("--foreground", action="store_true", help="Run Compose in the foreground")
    start_parser.add_argument(
        "--regenerate-secrets",
        action="store_true",
        help="Replace the local environment file (intended for a fresh installation)",
    )
    subparsers.add_parser("stop", help="Stop the local Aegis stack without deleting data")
    logs_parser = subparsers.add_parser("logs", help="Show local stack logs")
    logs_parser.add_argument("--follow", action="store_true", help="Continue streaming logs")
    upgrade_parser = subparsers.add_parser("upgrade", help="Upgrade Aegis and rebuild the local stack")
    upgrade_parser.add_argument("--no-start", action="store_true", help="Upgrade without restarting")
    backup_parser = subparsers.add_parser("backup", help="Back up PostgreSQL and generated reports")
    backup_parser.add_argument("--output", help="Backup zip path")
    restore_parser = subparsers.add_parser("restore", help="Restore a backup archive")
    restore_parser.add_argument("archive", help="Backup zip path")
    restore_parser.add_argument("--yes", action="store_true", help="Confirm replacement of current state")
    doctor_parser = subparsers.add_parser("doctor", help="Check local scanner dependencies")
    doctor_parser.add_argument("--json", action="store_true", help="Print doctor output as JSON")
    report_parser = subparsers.add_parser("report", help="Show or open the latest Aegis scan report")
    report_parser.add_argument("--dir", help="Directory containing report.html or report.md")
    report_parser.add_argument("--markdown", action="store_true", help="Use report.md instead of report.html")
    report_parser.add_argument("--open", action="store_true", help="Open the report with the system default app")
    report_parser.add_argument("--path", action="store_true", help="Print only the report path")
    demo_parser = subparsers.add_parser("demo", help="Create a tiny sample app, scan it, and print the report path")
    demo_parser.add_argument("--output", help="Directory for generated demo reports")
    demo_parser.add_argument("--open", action="store_true", help="Open the generated HTML report")
    subparsers.add_parser("version", help="Print Aegis version")

    args = parser.parse_args()

    if args.command == "scan":
        try:
            if args.json or args.quiet:
                sink = sys.stderr if args.json else open(os.devnull, "w")
                try:
                    with contextlib.redirect_stdout(sink):
                        summary = execute_scan(
                            args.path,
                            use_docker=not args.no_docker,
                            tool_timeout=args.timeout,
                            output_dir=args.output,
                            json_output=args.json,
                            quiet=args.quiet,
                            fail_on=args.fail_on,
                            fast=args.fast,
                            config_path=args.config,
                            sarif=args.sarif,
                            strict=args.strict,
                            return_summary=True,
                        )
                finally:
                    if not args.json:
                        sink.close()
                if args.json:
                    print(json.dumps(summary, indent=2))
                return summary.get("exit_code", EXIT_OPERATIONAL_ERROR)
            return execute_scan(
                args.path,
                use_docker=not args.no_docker,
                tool_timeout=args.timeout,
                output_dir=args.output,
                fail_on=args.fail_on,
                fast=args.fast,
                config_path=args.config,
                sarif=args.sarif,
                strict=args.strict,
            )
        except Exception as exc:
            error_summary = {
                "target": str(Path(args.path).expanduser().resolve()),
                "status": "error",
                "exit_code": EXIT_OPERATIONAL_ERROR,
                "error": str(exc),
            }
            if args.json:
                print(json.dumps(error_summary, indent=2))
            else:
                print(f"Aegis operational error: {exc}", file=sys.stderr)
            return EXIT_OPERATIONAL_ERROR
    elif args.command == "install-hook":
        return install_hook()
    elif args.command == "uninstall-hook":
        return uninstall_hook()
    elif args.command == "start":
        return run_start(
            no_open=args.no_open,
            foreground=args.foreground,
            regenerate_secrets=args.regenerate_secrets,
        )
    elif args.command == "stop":
        return run_stop()
    elif args.command == "logs":
        return run_stack_logs(follow=args.follow)
    elif args.command == "upgrade":
        return run_upgrade(no_start=args.no_start)
    elif args.command == "backup":
        return run_backup(args.output)
    elif args.command == "restore":
        return run_restore(args.archive, confirmed=args.yes)
    elif args.command == "doctor":
        return run_doctor(json_output=args.json)
    elif args.command == "report":
        return run_report(
            report_dir=args.dir,
            markdown=args.markdown,
            open_report=args.open,
            path_only=args.path,
        )
    elif args.command == "demo":
        return run_demo(open_report=args.open, output_dir=args.output)
    elif args.command == "version":
        print(get_package_version())
        return 0
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
