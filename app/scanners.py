import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable


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


SEMGREP_RULES = """rules:
  - id: python-sqli
    pattern-either:
      - pattern: $CURSOR.execute(f"...")
      - pattern: $CURSOR.execute("..." % ...)
      - pattern: $CURSOR.execute("...".format(...))
      - pattern: $CURSOR.execute($QUERY + ...)
    message: "Detected potential SQL injection via string formatting or interpolation in database execution."
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


def configure_semgrep_environment():
    os.environ.setdefault("SEMGREP_SEND_METRICS", "off")
    os.environ.setdefault(
        "SEMGREP_LOG_FILE",
        str(Path(tempfile.gettempdir()) / "aegis-semgrep.log"),
    )
    try:
        import certifi

        os.environ.setdefault("SSL_CERT_FILE", certifi.where())
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
        except Exception:
            pass

    return findings
