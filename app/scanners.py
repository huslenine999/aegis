import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


DEFAULT_IGNORED_DIRS = {
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

LogCallback = Callable[[str, str], None]

SCANNER_ENV_ALLOWLIST = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "TEMP",
    "TMP",
    "TMPDIR",
}


SEMGREP_RULES = """rules:
  - id: python-sqli
    mode: taint
    pattern-sources:
      - pattern: input(...)
      - pattern: $REQUEST.query_params
      - pattern: $REQUEST.path_params
      - pattern: $REQUEST.form(...)
      - pattern: $REQUEST.json(...)
    pattern-sinks:
      - patterns:
          - pattern: $CURSOR.execute($QUERY, ...)
          - focus-metavariable: $QUERY
      - patterns:
          - pattern: $CURSOR.executemany($QUERY, ...)
          - focus-metavariable: $QUERY
    message: "Untrusted request or input data reaches a database execution call. Use a parameterized query."
    languages: [python]
    severity: ERROR

  - id: python-rce
    patterns:
      - pattern-either:
          - pattern: subprocess.check_output(..., shell=True)
          - pattern: subprocess.run(..., shell=True)
          - pattern: subprocess.Popen(..., shell=True)
          - pattern: os.system(...)
    message: "Detected command injection risk via subprocess/os.system with shell=True."
    languages: [python]
    severity: ERROR

  - id: python-eval
    pattern: eval(...)
    message: "Detected unsafe use of eval()."
    languages: [python]
    severity: ERROR

  - id: python-pickle
    pattern: pickle.loads(...)
    message: "Detected unsafe deserialization with pickle."
    languages: [python]
    severity: ERROR

  - id: python-weak-hash
    pattern: hashlib.md5(...)
    message: "Detected weak MD5 hashing algorithm. Use SHA-256 or SHA-512 instead."
    languages: [python]
    severity: WARNING
"""


def scanner_subprocess_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key in SCANNER_ENV_ALLOWLIST
    }
    proxy = os.environ.get("AEGIS_SCANNER_HTTPS_PROXY")
    if proxy:
        environment["HTTPS_PROXY"] = proxy
    return environment


def find_runtime_executable(name: str, python_executable: str | None = None) -> str | None:
    """Find a scanner on PATH or beside the active Python/pipx interpreter."""
    located = shutil.which(name)
    if located:
        return located
    executable_name = f"{name}.exe" if os.name == "nt" else name
    adjacent = Path(python_executable or sys.executable).parent / executable_name
    is_executable = adjacent.is_file() and (
        os.name == "nt" or os.access(adjacent, os.X_OK)
    )
    return str(adjacent) if is_executable else None


def configure_semgrep_environment(environment: dict[str, str] | None = None):
    target = os.environ if environment is None else environment
    temp_dir = Path(tempfile.gettempdir())
    target.setdefault("SEMGREP_SEND_METRICS", "off")
    target.setdefault(
        "SEMGREP_SETTINGS_FILE",
        str(temp_dir / "aegis-semgrep-settings.yml"),
    )
    target.setdefault(
        "SEMGREP_LOG_FILE",
        str(temp_dir / "aegis-semgrep.log"),
    )
    try:
        import certifi

        target.setdefault("SSL_CERT_FILE", certifi.where())
    except ImportError:
        pass


def write_semgrep_rules(path: Path):
    path.parent.mkdir(exist_ok=True, parents=True)
    path.write_text(SEMGREP_RULES)


def should_skip_path(path: Path, ignored_dirs: set[str] = DEFAULT_IGNORED_DIRS) -> bool:
    return any(part in ignored_dirs for part in path.parts)


def _emit(log: LogCallback | None, message: str, level: str = "info"):
    if log:
        log(message, level)


def _response_json(response) -> dict[str, Any]:
    try:
        value = response.json()
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _dast_exploit_observed(probe_id: str, response, payload: str) -> bool:
    body = str(getattr(response, "text", "") or "")
    data = _response_json(response)
    if probe_id == "sql_injection":
        return bool(data.get("results"))
    if probe_id == "command_injection":
        output = str(data.get("output", body))
        return "root:" in output or "uid=" in output
    if probe_id == "unsafe_eval":
        return "AEGIS_RCE_PROBE" in body or "AEGIS_RCE_PROBE" in str(data)
    if probe_id == "path_traversal":
        return "Flask==" in body or "fastapi==" in body
    if probe_id == "reflected_xss":
        return payload in body
    if probe_id == "ssrf":
        return data.get("status") == "success" and bool(data.get("response"))
    return False


def run_dast_scan(
    target_url: str | None,
    *,
    internal_port: int = 5001,
    timeout: int = 3,
    log: LogCallback | None = None,
) -> list[dict[str, Any]]:
    """Run narrow probes and report exposure only when exploit effects are observed."""
    if not target_url:
        _emit(log, "[DAST] Skipped: no isolated target URL was available.", "muted")
        return []

    marker = "<script>window.AEGIS_XSS_PROBE=1</script>"
    probes: list[dict[str, Any]] = [
        {
            "id": "sql_injection",
            "vuln_type": "SQL Injection",
            "route": "/user",
            "params": {"name": "admin' OR '1'='1"},
            "payload": "admin' OR '1'='1",
            "description": "Injected SQL changed the returned row set.",
        },
        {
            "id": "command_injection",
            "vuln_type": "Remote Code Execution",
            "route": "/ping",
            "params": {"host": "127.0.0.1; cat /etc/passwd"},
            "payload": "127.0.0.1; cat /etc/passwd",
            "description": "Command output contained operating-system account data.",
        },
        {
            "id": "unsafe_eval",
            "vuln_type": "Unsafe Eval Injection",
            "route": "/calculate",
            "params": {
                "expr": "__import__('os').popen('printf AEGIS_RCE_PROBE').read()"
            },
            "payload": "__import__('os').popen('printf AEGIS_RCE_PROBE').read()",
            "description": "The response contained a marker produced by injected Python.",
        },
        {
            "id": "path_traversal",
            "vuln_type": "Path Traversal (LFI)",
            "route": "/download",
            "params": {"file": "../../../app/requirements.txt"},
            "payload": "../../../app/requirements.txt",
            "description": "The response exposed a file outside the download directory.",
        },
        {
            "id": "reflected_xss",
            "vuln_type": "Cross-Site Scripting (XSS)",
            "route": "/xss",
            "params": {"msg": marker},
            "payload": marker,
            "description": "The response reflected an executable script without escaping.",
        },
        {
            "id": "ssrf",
            "vuln_type": "Server-Side Request Forgery (SSRF)",
            "route": "/ssrf",
            "params": {"url": f"http://127.0.0.1:{internal_port}/health"},
            "payload": f"http://127.0.0.1:{internal_port}/health",
            "description": "The application fetched a loopback-only service and returned it.",
        },
    ]

    import requests

    findings = []
    for probe in probes:
        _emit(
            log,
            f"[DAST] Scanning route: {probe['route']} with a {probe['id']} probe.",
            "muted",
        )
        status_code = 0
        try:
            response = requests.get(
                f"{target_url}{probe['route']}",
                params=probe["params"],
                timeout=timeout,
                allow_redirects=False,
            )
            status_code = int(response.status_code)
            if status_code in {404, 405}:
                status = "NOT_APPLICABLE"
            elif status_code in {400, 401, 403, 422}:
                status = "MITIGATED"
            elif 200 <= status_code < 300:
                status = (
                    "EXPOSED"
                    if _dast_exploit_observed(probe["id"], response, probe["payload"])
                    else "MITIGATED"
                )
            else:
                status = "ERROR"
        except requests.RequestException:
            status = "ERROR"

        _emit(
            log,
            f"[DAST] Result for {probe['vuln_type']}: {status} (HTTP {status_code or 'error'})",
            "match" if status == "EXPOSED" else "info",
        )
        findings.append(
            {
                "vuln_type": probe["vuln_type"],
                "route": probe["route"],
                "payload": probe["payload"],
                "description": probe["description"],
                "status": status,
                "response_code": status_code or None,
            }
        )
    return findings


def _is_ignored_path(path: Path, ignored_paths: set[str]) -> bool:
    if not ignored_paths:
        return False

    resolved = path.resolve()
    path_text = str(path)
    resolved_text = str(resolved)
    for ignored in ignored_paths:
        ignored_path = Path(ignored)
        ignored_text = str(ignored_path)
        if path_text == ignored_text or path_text.endswith(f"{os.sep}{ignored_text}"):
            return True
        if path_text.startswith(f"{ignored_text}{os.sep}"):
            return True
        if resolved_text == ignored_text or resolved_text.endswith(f"{os.sep}{ignored_text}"):
            return True
        if resolved_text.startswith(f"{ignored_text}{os.sep}"):
            return True
    return False


def _iter_scan_files(
    target_path: Path,
    suffixes: tuple[str, ...],
    ignored_dirs: set[str],
    ignored_paths: set[str] | None = None,
):
    ignored_paths = ignored_paths or set()
    if target_path.is_dir():
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            if should_skip_path(Path(root), ignored_dirs):
                continue
            for file in files:
                file_path = Path(root) / file
                if file.endswith(suffixes) and not _is_ignored_path(file_path, ignored_paths):
                    yield file_path
    else:
        if not _is_ignored_path(target_path, ignored_paths):
            yield target_path


def run_yara_scan(
    target_path: str | Path,
    *,
    rules_path: str | Path | None = None,
    ignored_dirs: set[str] = DEFAULT_IGNORED_DIRS,
    ignored_paths: set[str] | None = None,
    log: LogCallback | None = None,
):
    findings = []
    target = Path(target_path)
    yara_rules_path = Path(rules_path) if rules_path else Path(__file__).resolve().parent.parent / "rules" / "aegis_rules.yar"

    try:
        import yara

        if yara_rules_path.exists():
            rules = yara.compile(filepath=str(yara_rules_path))

            for file_path in _iter_scan_files(target, (".py",), ignored_dirs, ignored_paths):
                try:
                    matches = rules.match(filepath=str(file_path))
                    for match in matches:
                        finding = {
                            "rule": match.rule,
                            "filename": str(file_path),
                            "description": match.meta.get("description", "YARA rule match"),
                            "author": match.meta.get("author", "Aegis"),
                        }
                        findings.append(finding)
                        _emit(log, f"[YARA] MATCH: {match.rule} in {file_path}", "match")
                except Exception as exc:
                    _emit(log, f"[YARA Error] {file_path}: {exc}", "error")
            return findings
    except ImportError:
        _emit(log, "[YARA] yara-python missing. Falling back to signature scan.", "muted")

    for file_path in _iter_scan_files(target, (".py",), ignored_dirs, ignored_paths):
        try:
            content = file_path.read_text(errors="ignore")

            if (
                re.search(r"eval\(\s*request\.(args|form|values)", content)
                or re.search(r"exec\(\s*request\.(args|form|values)", content)
                or re.search(r"subprocess\.Popen\(\s*request\.args", content)
                or re.search(r"subprocess\.check_output\(\s*request\.args", content)
            ):
                findings.append({
                    "rule": "Backdoor_Webshell",
                    "filename": str(file_path),
                    "description": "Detects Python webshell or remote command execution patterns",
                    "author": "Aegis (Fallback)",
                })
                _emit(log, f"[YARA Fallback] MATCH: Backdoor_Webshell in {file_path}", "match")

            if "base64.b64decode" in content and ("exec(" in content or "eval(" in content):
                findings.append({
                    "rule": "Obfuscated_Payload",
                    "filename": str(file_path),
                    "description": "Detects base64 obfuscation combined with execution",
                    "author": "Aegis (Fallback)",
                })
                _emit(log, f"[YARA Fallback] MATCH: Obfuscated_Payload in {file_path}", "match")

            has_sh = ("/bin/sh" in content) or ("/bin/bash" in content)
            has_pty = "pty.spawn" in content
            has_socket = "socket.socket" in content
            has_sub = ("subprocess.Popen" in content) or ("subprocess.call" in content)
            if (has_sh and has_pty) or (has_socket and has_sub and has_sh):
                findings.append({
                    "rule": "Suspicious_Shell_Spawn",
                    "filename": str(file_path),
                    "description": "Detects shell spawning commands, likely for reverse shells",
                    "author": "Aegis (Fallback)",
                })
                _emit(log, f"[YARA Fallback] MATCH: Suspicious_Shell_Spawn in {file_path}", "match")
        except Exception as exc:
            _emit(log, f"[Fallback Scan Error] {file_path}: {exc}", "error")

    return findings


def run_clamav_scan(
    target_path: str | Path,
    *,
    ignored_dirs: set[str] = DEFAULT_IGNORED_DIRS,
    ignored_paths: set[str] | None = None,
    timeout: int = 120,
    log: LogCallback | None = None,
):
    findings = []
    target = Path(target_path)
    clamscan_bin = shutil.which("clamscan")

    if clamscan_bin and not ignored_paths:
        try:
            _emit(log, "[ClamAV] Starting ClamAV scanning CLI...", "muted")
            result = subprocess.run(
                [clamscan_bin, "-r", "--infected", str(target)],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env=scanner_subprocess_environment(),
            )
            if result.returncode not in {0, 1}:
                raise RuntimeError(
                    f"clamscan exited with code {result.returncode}: {result.stderr[-500:]}"
                )
            for line in result.stdout.splitlines():
                if "FOUND" not in line:
                    continue
                parts = line.split(":")
                if len(parts) >= 2:
                    filename = parts[0].strip()
                    virus_part = parts[1].replace("FOUND", "").strip()
                    findings.append({
                        "filename": filename,
                        "virus": virus_part,
                        "description": f"ClamAV detected malware signature: {virus_part}",
                    })
                    _emit(log, f"[ClamAV] MATCH: {virus_part} in {filename}", "match")
            return findings
        except Exception as exc:
            _emit(log, f"[ClamAV Error] {exc}", "error")
            raise

    eicar_sig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    for file_path in _iter_scan_files(target, (".py", ".txt"), ignored_dirs, ignored_paths):
        try:
            content = file_path.read_text(errors="ignore")
            if eicar_sig in content:
                findings.append({
                    "filename": str(file_path),
                    "virus": "EICAR-Test-Signature",
                    "description": "Matched EICAR standard antivirus test signature",
                })
                _emit(log, f"[ClamAV Fallback] MATCH: EICAR-Test-Signature in {file_path}", "match")

            if re.search(r"(eval|exec)\(\s*base64\.b64decode", content):
                findings.append({
                    "filename": str(file_path),
                    "virus": "Python.Backdoor.Base64Decoder",
                    "description": "Detected base64-encoded Python execution pattern, indicating potential backdoor/webshell",
                })
                _emit(log, f"[ClamAV Fallback] MATCH: Python.Backdoor.Base64Decoder in {file_path}", "match")
        except (OSError, UnicodeError) as exc:
            _emit(log, f"[ClamAV Fallback] Unable to inspect {file_path}: {exc}", "muted")

    return findings
