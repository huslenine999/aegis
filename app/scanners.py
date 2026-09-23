import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Callable

from .resource_budgets import BoundedFindingList


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
    findings = BoundedFindingList()
    target = Path(target_path)
    yara_rules_path = Path(rules_path) if rules_path else Path(__file__).resolve().parent.parent / "rules" / "aegis_rules.yar"

    import yara
    if not yara_rules_path.is_file():
        raise FileNotFoundError(f"YARA rules not found: {yara_rules_path}")
    rules = yara.compile(filepath=str(yara_rules_path))
    for file_path in _iter_scan_files(target, (".py",), ignored_dirs, ignored_paths):
        matches = rules.match(filepath=str(file_path))
        for match in matches:
            findings.append({
                "rule": match.rule,
                "filename": str(file_path),
                "description": match.meta.get("description", "YARA rule match"),
                "author": match.meta.get("author", "Aegis"),
            })
            _emit(log, f"[YARA] MATCH: {match.rule} in {file_path}", "match")
    return findings
