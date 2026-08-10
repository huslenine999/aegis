"""Hardened, engine-neutral infrastructure-as-code scanning.

Checkov is deliberately kept behind this module.  The rest of Aegis consumes
the small report schema below rather than depending on Checkov's evolving JSON
shape or on paths emitted by a remote worker workspace.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml  # type: ignore[import-untyped]

from .scanners import DEFAULT_IGNORED_DIRS, find_runtime_executable, scanner_subprocess_environment


TOOL_NAME = "IaC"
ENGINE_NAME = "Checkov"
CHECKOV_VERSION = "3.1.0"
SUPPORTED_FRAMEWORKS = ("terraform", "cloudformation", "kubernetes", "dockerfile")
VALID_CHECKOV_EXIT_CODES = frozenset({0, 1})
MAX_CHECKOV_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_CHECKOV_REPORT_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 10_000

LogCallback = Callable[[str, str], None]


@dataclass(frozen=True)
class DiscoveredIaCFile:
    """A repository-relative candidate and the Checkov framework it belongs to."""

    path: str
    framework: str


@dataclass(frozen=True)
class IaCExecution:
    """Immutable execution result shared by the CLI and worker adapters."""

    status: str
    report: Mapping[str, Any]
    return_code: int | None = None
    detail: str | None = None


class IaCReportError(ValueError):
    """Raised when Checkov output cannot be trusted as JSON evidence."""


def _emit(log: LogCallback | None, message: str, level: str = "info") -> None:
    if log:
        log(message, level)


def _normalise_framework(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "tf": "terraform",
        "cfn": "cloudformation",
        "k8s": "kubernetes",
        "kube": "kubernetes",
        "docker": "dockerfile",
    }
    return aliases.get(text, text)


def _frameworks_in_order(values: Iterable[Any]) -> tuple[str, ...]:
    found = {_normalise_framework(value) for value in values}
    return tuple(framework for framework in SUPPORTED_FRAMEWORKS if framework in found)


def _is_excluded(path: Path, ignored_paths: frozenset[str]) -> bool:
    if not ignored_paths:
        return False
    raw = str(path)
    resolved = str(path.resolve())
    for ignored in ignored_paths:
        value = str(ignored)
        if raw == value or raw.endswith(f"{os.sep}{value}") or raw.startswith(f"{value}{os.sep}"):
            return True
        if resolved == value or resolved.endswith(f"{os.sep}{value}") or resolved.startswith(f"{value}{os.sep}"):
            return True
        if path.name == value and not Path(value).is_absolute():
            return True
    return False


def _repository_root(target_path: Path) -> Path:
    return target_path if target_path.is_dir() else target_path.parent


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _yaml_documents(path: Path) -> tuple[Any, ...]:
    try:
        if path.suffix.lower() in {".json", ".template"} or path.name.lower().endswith(".json"):
            value = json.loads(path.read_text(errors="replace"))
            return (value,)
        return tuple(document for document in yaml.safe_load_all(path.read_text(errors="replace")) if document is not None)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError):
        return ()


def _is_cloudformation_document(document: Any) -> bool:
    if not isinstance(document, dict):
        return False
    if isinstance(document.get("Resources"), dict):
        return True
    return False


def _is_kubernetes_document(document: Any) -> bool:
    return isinstance(document, dict) and bool(document.get("apiVersion")) and bool(document.get("kind"))


def _candidate_framework(path: Path) -> str | None:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    if suffix == ".tf" or name.endswith(".tf.json"):
        return "terraform"
    if suffix not in {".yaml", ".yml", ".json", ".template"} and not name.endswith(".template.json"):
        return None

    documents = _yaml_documents(path)
    if any(_is_kubernetes_document(document) for document in documents):
        return "kubernetes"
    if any(_is_cloudformation_document(document) for document in documents):
        return "cloudformation"
    return None


def discover_iac_files(
    target_path: str | Path,
    *,
    ignored_dirs: Iterable[str] = DEFAULT_IGNORED_DIRS,
    ignored_paths: Iterable[str] = (),
) -> tuple[DiscoveredIaCFile, ...]:
    """Discover supported IaC files without following symlinks or reading secrets."""

    target = Path(target_path).expanduser()
    if not target.exists():
        return ()
    ignored_dir_names = frozenset(str(item) for item in ignored_dirs)
    excluded = frozenset(str(Path(item).expanduser()) for item in ignored_paths)
    root = _repository_root(target)
    paths: list[Path] = []
    if target.is_dir():
        for current, directories, files in os.walk(target, followlinks=False):
            current_path = Path(current)
            directories[:] = [directory for directory in directories if directory not in ignored_dir_names]
            if any(part in ignored_dir_names for part in current_path.parts):
                continue
            for filename in files:
                candidate = current_path / filename
                if not candidate.is_symlink() and not _is_excluded(candidate, excluded):
                    paths.append(candidate)
    elif not target.is_symlink() and not _is_excluded(target, excluded):
        paths.append(target)

    discovered: list[DiscoveredIaCFile] = []
    for path in sorted(paths, key=lambda item: item.as_posix().lower()):
        framework = _candidate_framework(path)
        if framework:
            discovered.append(DiscoveredIaCFile(_relative_path(path, root), framework))
    return tuple(discovered)


def _validate_frameworks(frameworks: Iterable[str]) -> tuple[str, ...]:
    values = tuple(frameworks)
    selected = _frameworks_in_order(values)
    requested = {_normalise_framework(framework) for framework in values}
    unsupported = requested - set(SUPPORTED_FRAMEWORKS)
    if unsupported:
        raise ValueError(f"Unsupported IaC framework(s): {', '.join(sorted(unsupported))}")
    if not selected:
        raise ValueError("At least one IaC framework is required.")
    return selected


def build_checkov_command(
    checkov_executable: str,
    target_path: str | Path,
    frameworks: Iterable[str],
    *,
    config_path: str | Path,
    skipped_paths: Iterable[str] = (),
    input_paths: Iterable[str | Path] = (),
) -> tuple[str, ...]:
    """Build the only Checkov command Aegis is allowed to execute."""

    selected = _validate_frameworks(frameworks)
    target = Path(target_path)
    selected_inputs = tuple(str(path) for path in input_paths if str(path))
    command: list[str] = [checkov_executable]
    if target.is_dir() and selected_inputs:
        command.extend(["--file", *selected_inputs])
    else:
        command.extend(["--directory" if target.is_dir() else "--file", str(target)])
    command.extend([
        "--framework", *selected,
        "--output", "json",
        "--quiet",
        "--compact",
        "--download-external-modules", "false",
        "--skip-download",
        "--config-file", str(config_path),
    ])
    safe_skips = sorted({str(path) for path in skipped_paths if str(path)})
    if safe_skips:
        command.extend(["--skip-path", ",".join(safe_skips)])
    return tuple(command)


def parse_checkov_output(output: str | bytes, *, max_bytes: int = MAX_CHECKOV_OUTPUT_BYTES) -> Any:
    """Parse strict JSON; logs or truncated output are operational failures."""

    raw = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
    if len(raw.encode("utf-8")) > max_bytes:
        raise IaCReportError("Checkov JSON output exceeded the configured size limit.")
    if not raw.strip():
        raise IaCReportError("Checkov produced empty output.")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IaCReportError("Checkov produced malformed JSON output.") from exc


def _looks_like_checkov_payload(payload: Any) -> bool:
    """Require a recognizable Checkov result envelope before normalizing it."""

    result_keys = {"results", "passed_checks", "failed_checks", "skipped_checks"}
    if isinstance(payload, list):
        return any(
            isinstance(item, dict)
            and (
                bool(result_keys.intersection(item))
                or any(key in item for key in ("check_type", "framework", "framework_type"))
            )
            for item in payload
        )
    if not isinstance(payload, dict):
        return False
    if result_keys.intersection(payload) or any(
        key in payload for key in ("check_type", "framework", "framework_type")
    ):
        return True
    return any(
        _normalise_framework(key) in SUPPORTED_FRAMEWORKS and isinstance(value, dict)
        for key, value in payload.items()
    )


def _payloads(payload: Any) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        if any(key in payload for key in ("check_type", "framework", "framework_type")):
            values = [payload]
        elif any(_normalise_framework(key) in SUPPORTED_FRAMEWORKS for key in payload):
            values = [
                {"check_type": key, **value}
                for key, value in payload.items()
                if _normalise_framework(key) in SUPPORTED_FRAMEWORKS and isinstance(value, dict)
            ]
        else:
            values = [payload]
    else:
        return ()

    result: list[tuple[str, Mapping[str, Any]]] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        framework = _normalise_framework(
            value.get("check_type") or value.get("framework") or value.get("framework_type")
        )
        result.append((framework, value))
    return tuple(result)


def _result_groups(value: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    results = value.get("results")
    if isinstance(results, dict):
        return tuple(
            (key, results.get(key, []))
            for key in ("passed_checks", "failed_checks", "skipped_checks")
            if isinstance(results.get(key), list)
        )
    groups: list[tuple[str, Any]] = []
    for key in ("passed_checks", "failed_checks", "skipped_checks"):
        if isinstance(value.get(key), list):
            groups.append((key, value[key]))
    if isinstance(results, list):
        groups.append(("results", results))
    return tuple(groups)


def _check_status(group: str, item: Mapping[str, Any]) -> str:
    if group == "passed_checks":
        return "PASSED"
    if group == "failed_checks":
        return "FAILED"
    if group == "skipped_checks":
        return "SKIPPED"
    check_result = item.get("check_result")
    if isinstance(check_result, dict):
        check_result = check_result.get("result")
    if check_result is True or str(check_result).upper() in {"PASSED", "PASS", "TRUE"}:
        return "PASSED"
    if check_result is False or str(check_result).upper() in {"FAILED", "FAIL", "FALSE"}:
        return "FAILED"
    return "SKIPPED" if item.get("suppress_comment") else "FAILED"


def _severity(value: Any) -> str:
    normalized = str(value or "").strip().upper()
    return normalized if normalized in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"


def _line_range(item: Mapping[str, Any]) -> tuple[int, int]:
    value = item.get("file_line_range") or item.get("line_range")
    if isinstance(value, Mapping):
        start = value.get("start") or value.get("start_line") or value.get("line") or 1
        end = value.get("end") or value.get("end_line") or start
    elif isinstance(value, (list, tuple)) and value:
        start = value[0]
        end = value[1] if len(value) > 1 else value[0]
    else:
        start = item.get("start_line") or item.get("line_number") or 1
        end = item.get("end_line") or start
    try:
        start_line = max(1, int(start))
    except (TypeError, ValueError):
        start_line = 1
    try:
        end_line = max(start_line, int(end))
    except (TypeError, ValueError):
        end_line = start_line
    return start_line, end_line


def _safe_relative_path(value: Any, root: Path) -> str:
    raw = str(value or "").replace("\\", "/").strip()
    if not raw:
        return ""
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            candidate_from_root = root / raw.lstrip("/")
            if candidate_from_root.is_file():
                return candidate_from_root.resolve().relative_to(root.resolve()).as_posix()
            raw = raw.lstrip("/")
    cleaned = Path(raw).as_posix()
    while cleaned.startswith("../"):
        cleaned = cleaned[3:]
    if cleaned in {"", ".", ".."}:
        return ""
    return cleaned


def _item_path(item: Mapping[str, Any]) -> Any:
    return item.get("repo_file_path") or item.get("file_path") or item.get("path") or item.get("file")


def _item_resource(item: Mapping[str, Any]) -> str:
    return str(item.get("resource") or item.get("resource_id") or item.get("entity") or "")[:1000]


def _item_rule(item: Mapping[str, Any]) -> str:
    return str(item.get("check_id") or item.get("bc_check_id") or item.get("rule_id") or "UNKNOWN")[:255]


def _item_title(item: Mapping[str, Any], rule_id: str) -> str:
    return str(item.get("check_name") or item.get("name") or item.get("title") or rule_id)[:2000]


def _item_guideline(item: Mapping[str, Any]) -> str:
    return str(item.get("guideline") or item.get("guide") or item.get("remediation_url") or "")[:2000]


def _inline_suppression_evidence(root: Path, discovered: Sequence[DiscoveredIaCFile]) -> tuple[dict[str, Any], ...]:
    """Collect repository suppressions without treating them as Aegis approvals."""

    candidates = {item.path for item in discovered}
    evidence: list[dict[str, Any]] = []
    for relative in sorted(candidates):
        path = root / relative
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if "checkov:skip" not in line.lower():
                continue
            match = re.search(r"checkov:skip\s*=\s*([^#\s:]+)(?:\s*:\s*(.*))?", line, re.IGNORECASE)
            rule = match.group(1) if match else "UNKNOWN"
            comment = (match.group(2) if match else "") or ""
            evidence.append({
                "rule_id": rule[:255],
                "path": relative,
                "start_line": line_number,
                "end_line": line_number,
                "comment": comment.strip()[:1000],
                "source": "repository-inline-checkov",
            })
    return tuple(evidence)


def normalize_checkov_report(
    payload: Any,
    target_path: str | Path,
    discovered: Sequence[DiscoveredIaCFile] = (),
    *,
    engine_version: str = CHECKOV_VERSION,
) -> dict[str, Any]:
    """Convert Checkov output to the Aegis-owned report schema."""

    target = Path(target_path)
    root = _repository_root(target)
    discovered_frameworks = [item.framework for item in discovered]
    findings_by_key: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    suppression_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    passed = failed = skipped = 0
    frameworks: list[str] = list(discovered_frameworks)

    for framework_from_payload, value in _payloads(payload):
        framework = framework_from_payload if framework_from_payload in SUPPORTED_FRAMEWORKS else ""
        if framework:
            frameworks.append(framework)
        for group, raw_items in _result_groups(value):
            for raw_item in raw_items:
                if not isinstance(raw_item, dict):
                    continue
                status = _check_status(group, raw_item)
                if status == "PASSED":
                    passed += 1
                    continue
                if status == "SKIPPED":
                    skipped += 1
                else:
                    failed += 1
                rule_id = _item_rule(raw_item)
                path = _safe_relative_path(_item_path(raw_item), root)
                start_line, end_line = _line_range(raw_item)
                item_framework = framework or _normalise_framework(raw_item.get("check_type"))
                if item_framework not in SUPPORTED_FRAMEWORKS:
                    item_framework = next(
                        (entry.framework for entry in discovered if entry.path == path),
                        "unknown",
                    )
                frameworks.append(item_framework)
                resource = _item_resource(raw_item)
                key = (item_framework, rule_id, resource, path)
                if status == "SKIPPED":
                    suppression_key = (rule_id, resource, path)
                    suppression_by_key.setdefault(
                        suppression_key,
                        {
                            "rule_id": rule_id,
                            "title": _item_title(raw_item, rule_id),
                            "framework": item_framework,
                            "resource": resource,
                            "path": path,
                            "start_line": start_line,
                            "end_line": end_line,
                            "source": "checkov-skipped-check",
                        },
                    )
                    continue
                finding = {
                    "rule_id": rule_id,
                    "title": _item_title(raw_item, rule_id),
                    "framework": item_framework,
                    "severity": _severity(raw_item.get("severity")),
                    "resource": resource,
                    "path": path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "remediation": str(raw_item.get("remediation") or "Review the Checkov finding and apply the least-privilege configuration.")[:4000],
                    "remediation_url": _item_guideline(raw_item),
                }
                existing = findings_by_key.get(key)
                if existing is None or existing["severity"] == "LOW" and finding["severity"] != "LOW":
                    findings_by_key[key] = finding

    for suppression in _inline_suppression_evidence(root, discovered):
        suppression_key = (suppression["rule_id"], "", suppression["path"])
        suppression_by_key.setdefault(
            suppression_key,
            {
                **suppression,
                "title": f"Inline Checkov suppression for {suppression['rule_id']}",
                "framework": next(
                    (item.framework for item in discovered if item.path == suppression["path"]),
                    "unknown",
                ),
                "resource": "",
            },
        )

    unmanaged = tuple(sorted(suppression_by_key.values(), key=lambda item: (
        str(item.get("path")), str(item.get("start_line")), str(item.get("rule_id"))
    )))
    frameworks_tuple = _frameworks_in_order(frameworks)
    candidate = passed + failed + skipped
    report = {
        "schema_version": 1,
        "tool": TOOL_NAME,
        "engine": {"name": ENGINE_NAME, "version": engine_version or "unknown"},
        "frameworks": list(frameworks_tuple),
        "summary": {
            "candidate": candidate,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        },
        "findings": list(findings_by_key.values())[:MAX_FINDINGS],
        "unmanaged_suppressions": list(unmanaged)[:MAX_FINDINGS],
        "status": "completed",
    }
    return report


def empty_iac_report(*, status: str = "skipped", detail: str | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": 1,
        "tool": TOOL_NAME,
        "engine": {"name": ENGINE_NAME, "version": CHECKOV_VERSION},
        "frameworks": [],
        "summary": {"candidate": 0, "passed": 0, "failed": 0, "skipped": 0},
        "findings": [],
        "unmanaged_suppressions": [],
        "status": status,
    }
    if detail:
        report["detail"] = detail[:500]
    return report


def _checkov_version() -> str:
    try:
        return importlib.metadata.version(ENGINE_NAME.lower())
    except importlib.metadata.PackageNotFoundError:
        return CHECKOV_VERSION


def _write_owned_config(path: Path) -> None:
    path.write_text(
        "download-external-modules: false\n"
        "skip-download: true\n"
        "external-checks-dir: []\n"
    )


def _failure_report(detail: str) -> dict[str, Any]:
    report = empty_iac_report(status="failed", detail=detail)
    report["error"] = {"code": "operational_failure", "message": detail[:500]}
    return report


def run_iac_scan(
    target_path: str | Path,
    *,
    report_path: str | Path | None = None,
    ignored_paths: Iterable[str] = (),
    timeout: int = 120,
    checkov_executable: str | None = None,
    log: LogCallback | None = None,
) -> IaCExecution:
    """Execute Checkov safely and persist only normalized Aegis evidence."""

    target = Path(target_path).expanduser().resolve()
    ignored_paths = tuple(str(path) for path in ignored_paths)
    discovered = discover_iac_files(target, ignored_paths=ignored_paths)
    output_path = Path(report_path) if report_path is not None else None

    def finish(execution: IaCExecution) -> IaCExecution:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            encoded = json.dumps(dict(execution.report), indent=2) + "\n"
            if len(encoded.encode("utf-8")) > MAX_CHECKOV_REPORT_BYTES:
                fallback = _failure_report("Normalized IaC report exceeded the configured size limit.")
                output_path.write_text(json.dumps(fallback, indent=2) + "\n")
                return IaCExecution("failed", fallback, detail="normalized report exceeded size limit")
            output_path.write_text(encoded)
        return execution

    if not discovered:
        _emit(log, "[IaC] No supported Terraform, CloudFormation, Kubernetes, or Dockerfile candidates found.", "muted")
        return finish(IaCExecution("completed", empty_iac_report(status="completed", detail="no supported IaC files found")))
    if timeout <= 0:
        return finish(IaCExecution("failed", _failure_report("IaC scanner timeout must be greater than zero."), detail="invalid timeout"))

    executable = checkov_executable or find_runtime_executable("checkov", sys.executable)
    if not executable:
        detail = "Checkov executable not found. Install the scanner extra before running an enforcing scan."
        _emit(log, f"[IaC Error] {detail}", "error")
        return finish(IaCExecution("failed", _failure_report(detail), detail=detail))

    frameworks = _frameworks_in_order(item.framework for item in discovered)
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-iac-") as temporary:
            temporary_root = Path(temporary)
            config_path = temporary_root / "checkov.yml"
            _write_owned_config(config_path)
            environment = scanner_subprocess_environment()
            environment.update({
                "HOME": str(temporary_root / "home"),
                "TMPDIR": str(temporary_root / "tmp"),
                "TEMP": str(temporary_root / "tmp"),
                "XDG_CACHE_HOME": str(temporary_root / "cache"),
                "DO_NOT_TRACK": "1",
                "CHECKOV_DISABLE_TELEMETRY": "1",
            })
            for directory in (environment["HOME"], environment["TMPDIR"], environment["XDG_CACHE_HOME"]):
                Path(directory).mkdir(parents=True, exist_ok=True)
            command = build_checkov_command(
                executable,
                target,
                frameworks,
                config_path=config_path,
                skipped_paths=ignored_paths,
                input_paths=(target / item.path for item in discovered),
            )
            _emit(log, f"[IaC] Running Checkov across {', '.join(frameworks)}.", "muted")
            try:
                completed = subprocess.run(
                    list(command),
                    cwd=temporary_root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                detail = f"Checkov timed out after {timeout}s."
                _emit(log, f"[IaC Error] {detail}", "error")
                return finish(IaCExecution("failed", _failure_report(detail), detail=detail))
            except (OSError, subprocess.SubprocessError) as exc:
                detail = f"Checkov execution failed: {type(exc).__name__}."
                _emit(log, f"[IaC Error] {detail}", "error")
                return finish(IaCExecution("failed", _failure_report(detail), detail=detail))

            try:
                payload = parse_checkov_output(completed.stdout)
                if not _looks_like_checkov_payload(payload):
                    raise IaCReportError("Checkov produced a malformed report envelope.")
            except IaCReportError as exc:
                detail = str(exc)
                _emit(log, f"[IaC Error] {detail}", "error")
                return finish(IaCExecution("failed", _failure_report(detail), return_code=completed.returncode, detail=detail))
            if completed.returncode not in VALID_CHECKOV_EXIT_CODES:
                detail = f"Checkov exited with unexpected code {completed.returncode}."
                _emit(log, f"[IaC Error] {detail}", "error")
                return finish(IaCExecution("failed", _failure_report(detail), return_code=completed.returncode, detail=detail))
            report = normalize_checkov_report(
                payload,
                target,
                discovered,
                engine_version=_checkov_version(),
            )
            _emit(log, f"[IaC] Checkov completed with {report['summary']['failed']} failed checks.", "match" if report["summary"]["failed"] else "info")
            return finish(IaCExecution("completed", report, return_code=completed.returncode))
    except OSError as exc:
        detail = f"IaC scanner setup failed: {type(exc).__name__}."
        return finish(IaCExecution("failed", _failure_report(detail), detail=detail))


# Explicit alias keeps the contract discoverable for callers that use the
# scanner verb rather than the execution verb.
scan_iac = run_iac_scan


__all__ = [
    "CHECKOV_VERSION",
    "DiscoveredIaCFile",
    "IaCExecution",
    "IaCReportError",
    "SUPPORTED_FRAMEWORKS",
    "build_checkov_command",
    "discover_iac_files",
    "empty_iac_report",
    "normalize_checkov_report",
    "parse_checkov_output",
    "run_iac_scan",
    "scan_iac",
]
