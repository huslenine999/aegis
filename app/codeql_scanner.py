"""Operator-provisioned CodeQL runner and bounded SARIF normalization."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote, urlsplit

from .resource_budgets import (
    ResourceLimitError,
    load_bounded_json,
    resource_budgets,
    run_bounded_subprocess,
    run_bounded_subprocess_stdout_to_file,
    run_bounded_subprocess_to_file,
)


SUPPORTED_LANGUAGES = {"python", "javascript-typescript"}
SOURCE_SUFFIXES = {
    ".py": "python", ".js": "javascript-typescript", ".jsx": "javascript-typescript",
    ".ts": "javascript-typescript", ".tsx": "javascript-typescript",
    ".mjs": "javascript-typescript", ".cjs": "javascript-typescript",
}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def operator_runtime_configuration() -> tuple[str, dict[str, str]]:
    """Read only operator-owned CodeQL runtime settings, never repository config."""
    image = os.environ.get("AEGIS_CODEQL_IMAGE", "").strip()
    suites = {
        language: value
        for language, key in (
            ("python", "AEGIS_CODEQL_PYTHON_SUITE"),
            ("javascript-typescript", "AEGIS_CODEQL_JAVASCRIPT_SUITE"),
        )
        if (value := os.environ.get(key, "").strip())
    }
    if not image:
        raise CodeQLScanError("Pinned isolated CodeQL image is not provisioned.")
    return image, suites


class CodeQLScanError(RuntimeError):
    """CodeQL could not establish complete, trusted analysis output."""


def _local_path(uri: str, source: Path) -> str:
    if not isinstance(uri, str) or not uri or "\\" in uri or "\x00" in uri:
        raise CodeQLScanError("CodeQL SARIF contains an invalid source path.")
    parsed = urlsplit(uri)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise CodeQLScanError("CodeQL SARIF contains a non-local source path.")
    decoded = unquote(uri)
    path = Path(decoded)
    if decoded in {"", "."} or path.is_absolute() or any(part == ".." for part in path.parts):
        raise CodeQLScanError("CodeQL SARIF path escapes the source snapshot.")
    resolved = (source / path).resolve(strict=False)
    try:
        return resolved.relative_to(source.resolve()).as_posix()
    except ValueError as exc:
        raise CodeQLScanError("CodeQL SARIF path escapes the source snapshot.") from exc


def _location(value: object, source: Path) -> dict:
    if not isinstance(value, dict):
        raise CodeQLScanError("CodeQL SARIF has an invalid location.")
    physical = value.get("physicalLocation")
    if not isinstance(physical, dict):
        raise CodeQLScanError("CodeQL SARIF has no physical location.")
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        raise CodeQLScanError("CodeQL SARIF has no artifact location.")
    base = artifact.get("uriBaseId")
    if base not in (None, "%SRCROOT%"):
        raise CodeQLScanError("CodeQL SARIF uses an untrusted URI base.")
    uri = artifact.get("uri")
    if not isinstance(uri, str):
        raise CodeQLScanError("CodeQL SARIF has an invalid source path.")
    filename = _local_path(uri, source)
    region = physical.get("region") or {}
    line = region.get("startLine") if isinstance(region, dict) else None
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise CodeQLScanError("CodeQL SARIF has an invalid source line.")
    return {"filename": filename, "line_number": line}


def _severity(rule: dict, result: dict) -> str:
    properties = rule.get("properties") or {}
    score = properties.get("security-severity") if isinstance(properties, dict) else None
    if score is not None:
        try:
            value = float(score)
        except (TypeError, ValueError) as exc:
            raise CodeQLScanError("CodeQL SARIF has invalid security severity.") from exc
        if not 0 <= value <= 10:
            raise CodeQLScanError("CodeQL SARIF has invalid security severity.")
        return "CRITICAL" if value >= 9 else "HIGH" if value >= 7 else "MEDIUM" if value >= 4 else "LOW"
    defaults = rule.get("defaultConfiguration") or {}
    level = result.get("level", defaults.get("level", "warning")) if isinstance(defaults, dict) else "warning"
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}.get(str(level), "MEDIUM")


def _flow_locations(result: dict, source: Path) -> list[list[dict]]:
    flows = result.get("codeFlows") or []
    if not isinstance(flows, list):
        raise CodeQLScanError("CodeQL SARIF has invalid code flows.")
    normalized = []
    for flow in flows:
        if not isinstance(flow, dict) or not isinstance(flow.get("threadFlows"), list):
            raise CodeQLScanError("CodeQL SARIF has invalid code flows.")
        for thread in flow["threadFlows"]:
            if not isinstance(thread, dict) or not isinstance(thread.get("locations"), list):
                raise CodeQLScanError("CodeQL SARIF has invalid code flows.")
            points = []
            for item in thread["locations"]:
                if not isinstance(item, dict):
                    raise CodeQLScanError("CodeQL SARIF has invalid code flows.")
                location = item.get("location")
                if not isinstance(location, dict):
                    raise CodeQLScanError("CodeQL SARIF has invalid code flows.")
                point = _location(location, source)
                message = location.get("message", {})
                point["message"] = message.get("text", "") if isinstance(message, dict) else ""
                points.append(point)
            normalized.append(points)
    return normalized


def _parse_document(document: object, source: Path, language: str) -> list[dict]:
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise CodeQLScanError("CodeQL did not produce SARIF 2.1.0.")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise CodeQLScanError("CodeQL SARIF has no completed runs.")
    findings = []
    for run in runs:
        if not isinstance(run, dict):
            raise CodeQLScanError("CodeQL SARIF has an invalid run.")
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        invocations = run.get("invocations")
        category = run.get("automationDetails") or {}
        category_id = category.get("id") if isinstance(category, dict) else None
        if (
            not isinstance(driver, dict) or driver.get("name") not in {"CodeQL", "CodeQL command-line toolchain"}
            or (invocations is not None and (not isinstance(invocations, list) or any(
                not isinstance(item, dict) or item.get("executionSuccessful") is not True for item in invocations
            )))
            or category_id not in {language, f"{language}/", f"/language:{language}"}
        ):
            raise CodeQLScanError("CodeQL SARIF run is incomplete or for another language.")
        rules = driver.get("rules") or []
        results = run.get("results")
        if not isinstance(rules, list) or not isinstance(results, list):
            raise CodeQLScanError("CodeQL SARIF has invalid rules or results.")
        for item in results:
            if not isinstance(item, dict):
                raise CodeQLScanError("CodeQL SARIF has an invalid result.")
            index = item.get("ruleIndex")
            if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(rules):
                raise CodeQLScanError("CodeQL SARIF rule index is invalid.")
            rule = rules[index]
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                raise CodeQLScanError("CodeQL SARIF rule is invalid.")
            message = item.get("message")
            locations = item.get("locations")
            if not isinstance(message, dict) or not isinstance(message.get("text"), str) or not isinstance(locations, list) or not locations:
                raise CodeQLScanError("CodeQL SARIF result is incomplete.")
            first = _location(locations[0], source)
            properties = rule.get("properties") or {}
            if not isinstance(properties, dict):
                raise CodeQLScanError("CodeQL SARIF rule properties are invalid.")
            tags = properties.get("tags") or []
            if not isinstance(tags, list):
                raise CodeQLScanError("CodeQL SARIF rule tags are invalid.")
            cwe = sorted({f"CWE-{match.group(1).upper()}" for tag in tags if isinstance(tag, str)
                          if (match := re.search(r"cwe[-/](\d+)", tag, re.I))})
            partial = item.get("partialFingerprints") or {}
            if not isinstance(partial, dict):
                raise CodeQLScanError("CodeQL SARIF fingerprints are invalid.")
            fingerprint = partial.get("primaryLocationLineHash")
            if not isinstance(fingerprint, str) or not fingerprint:
                fingerprint = hashlib.sha256(json.dumps([rule["id"], first["filename"], first["line_number"], message["text"]], separators=(",", ":")).encode()).hexdigest()
            findings.append({
                "tool": "CodeQL", "language": language, "rule_id": rule["id"],
                "severity": _severity(rule, item), "cwe": cwe,
                "filename": first["filename"], "line_number": first["line_number"],
                "issue_text": message["text"], "fingerprint": fingerprint,
                "code_flows": _flow_locations(item, source),
            })
            if len(findings) > resource_budgets().max_scanner_findings:
                raise CodeQLScanError("CodeQL findings exceed the configured limit.")
    return findings


def parse_codeql_sarif(report: Path, source: Path, *, language: str) -> list[dict]:
    """Read every completed run; reject external paths and incomplete results."""
    if language not in SUPPORTED_LANGUAGES:
        raise CodeQLScanError("Unsupported CodeQL language.")
    try:
        return _parse_document(load_bounded_json(Path(report)), Path(source), language)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, ResourceLimitError, AttributeError, TypeError, KeyError) as exc:
        raise CodeQLScanError("CodeQL SARIF is missing, oversized, or malformed.") from exc


def _detected_languages(source: Path) -> list[str]:
    if source.is_file():
        language = SOURCE_SUFFIXES.get(source.suffix.lower())
        return [language] if language else []
    found: set[str] = set()
    for root, dirs, files in os.walk(source):
        dirs[:] = [name for name in dirs if name not in IGNORED_DIRS]
        found.update(SOURCE_SUFFIXES[Path(name).suffix.lower()] for name in files if Path(name).suffix.lower() in SOURCE_SUFFIXES)
    return sorted(found)


def _trusted_file(path: Path, source: Path, output: Path, *, executable: bool) -> Path:
    candidate = path.expanduser().absolute()
    if source == candidate or source in candidate.parents or output == candidate or output in candidate.parents:
        raise CodeQLScanError("CodeQL executable and query suites must be outside the target and output.")
    if not candidate.is_file() or not stat.S_ISREG(candidate.stat().st_mode):
        raise CodeQLScanError("CodeQL executable or query suite is missing or untrusted.")
    resolved = candidate.resolve()
    if source == resolved or source in resolved.parents or output == resolved or output in resolved.parents:
        raise CodeQLScanError("CodeQL executable and query suites must be outside the target and output.")
    if executable and not os.access(resolved, os.X_OK):
        raise CodeQLScanError("CodeQL executable is not executable.")
    return resolved


def run_codeql_scan(
    source: Path,
    output: Path,
    *,
    codeql_path: Path | None = None,
    query_suites: dict[str, Path] | None = None,
    languages: list[str] | None = None,
) -> dict:
    """Run buildless CodeQL with operator-owned suites and explicit coverage.

    OS isolation is enforced by the caller's runtime; this adapter never claims it.
    """
    source, output = Path(source).resolve(), Path(output).resolve()
    if not source.exists() or (source.is_file() and source.suffix.lower() not in SOURCE_SUFFIXES):
        raise CodeQLScanError("CodeQL source snapshot is missing or unsupported.")
    if source == output or source in output.parents or output in source.parents:
        raise CodeQLScanError("CodeQL output must be outside the source snapshot.")
    selected = languages if languages is not None else _detected_languages(source)
    if not selected or any(language not in SUPPORTED_LANGUAGES for language in selected) or len(selected) != len(set(selected)):
        raise CodeQLScanError("Deep scan has no supported CodeQL language or an invalid language selection.")
    configured_path = codeql_path or os.environ.get("AEGIS_CODEQL_PATH")
    if not configured_path:
        raise CodeQLScanError("CodeQL runtime is not provisioned.")
    binary = _trusted_file(Path(configured_path), source, output, executable=True)
    suites = query_suites or {
        language: Path(os.environ[f"AEGIS_CODEQL_{language.upper().replace('-', '_')}_SUITE"])
        for language in selected if os.environ.get(f"AEGIS_CODEQL_{language.upper().replace('-', '_')}_SUITE")
    }
    if set(suites) != set(selected):
        raise CodeQLScanError("Required CodeQL query suite is not provisioned.")
    trusted_suites = {language: _trusted_file(Path(suites[language]), source, output, executable=False) for language in selected}
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() for name in ("codeql.sarif", "codeql-report.json")):
        raise CodeQLScanError("CodeQL output artifacts already exist.")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=".codeql-", dir=output) as work:
        workspace = Path(work)
        env = {"PATH": os.defpath, "LANG": "C.UTF-8", "HOME": work, "TMPDIR": work}
        try:
            with (workspace / "version.txt").open("wb") as sink:
                version_result = run_bounded_subprocess([str(binary), "version"], env=env, stdout_sink=sink, timeout=30)
            if version_result.returncode != 0:
                raise CodeQLScanError("CodeQL version check failed.")
            version_match = re.search(r"\b\d+\.\d+\.\d+\b", (workspace / "version.txt").read_text(errors="replace"))
            if not version_match:
                raise CodeQLScanError("CodeQL version could not be established.")
            all_runs, findings = [], []
            source_root = source
            if source.is_file():
                source_root = workspace / "single-source"
                source_root.mkdir()
                shutil.copy2(source, source_root / source.name)
            for language in selected:
                database = workspace / f"db-{language}"
                create = [str(binary), "database", "create", str(database),
                          f"--language={language}", "--build-mode=none", f"--source-root={source_root}", "--threads=2", "--ram=2048"]
                if run_bounded_subprocess(create, env=env, timeout=600).returncode != 0:
                    raise CodeQLScanError(f"CodeQL database creation failed for {language}.")
                sarif = workspace / f"{language}.sarif"
                analyze = [str(binary), "database", "analyze", str(database), str(trusted_suites[language]),
                           "--format=sarifv2.1.0", f"--sarif-category={language}", f"--output={sarif}",
                           "--threads=2", "--ram=2048"]
                if run_bounded_subprocess_to_file(analyze, output_path=sarif, env=env, timeout=600).returncode != 0:
                    raise CodeQLScanError(f"CodeQL analysis failed for {language}.")
                try:
                    document = load_bounded_json(sarif)
                    findings.extend(parse_codeql_sarif(sarif, source_root, language=language))
                    if len(findings) > resource_budgets().max_scanner_findings:
                        raise CodeQLScanError("CodeQL findings exceed the configured limit.")
                    all_runs.extend(document["runs"])
                except FileNotFoundError as exc:
                    raise CodeQLScanError(f"CodeQL analysis produced missing SARIF for {language}.") from exc
            raw = {"version": "2.1.0", "runs": all_runs}
            encoded = json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode()
            if len(encoded) > resource_budgets().max_scanner_report_bytes:
                raise CodeQLScanError("Combined CodeQL SARIF exceeds the configured limit.")
            report = {
                "status": "completed",
                "coverage": {"complete": True, "languages": selected, "source_scope": "file" if source.is_file() else "repository", "isolation": "unverified"},
                "tool": {"name": "CodeQL", "version": version_match.group()},
                "query_suites": {language: _sha256_file(trusted_suites[language]) for language in selected},
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "findings": findings,
            }
            (workspace / "combined.sarif").write_bytes(encoded)
            (workspace / "report.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
            os.replace(workspace / "combined.sarif", output / "codeql.sarif")
            os.replace(workspace / "report.json", output / "codeql-report.json")
            return report
        except (OSError, subprocess.SubprocessError, ResourceLimitError, json.JSONDecodeError, UnicodeError) as exc:
            raise CodeQLScanError(f"CodeQL execution failed: {type(exc).__name__}.") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_tar(source: Path, destination: Path) -> None:
    """Stream only regular files from the admitted snapshot into CodeQL."""
    with tarfile.open(destination, "w", dereference=False) as archive:
        if source.is_file():
            archive.add(source, arcname=source.name, recursive=False)
            return
        for root, dirs, files in os.walk(source):
            dirs[:] = [name for name in dirs if name not in IGNORED_DIRS]
            base = Path(root)
            for name in files:
                path = base / name
                if path.is_file() and not path.is_symlink():
                    archive.add(path, arcname=path.relative_to(source), recursive=False)


def _docker_base(binary: Path, image: str, name: str, mounts: list[str]) -> list[str]:
    return [
        str(binary), "run", "--rm", "--name", name, "--pull=never",
        "--network=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true", "--pids-limit=128",
        "--memory=4g", "--cpus=2", "--user=10001:10001",
        "--tmpfs=/work:rw,nosuid,nodev,size=2g,mode=1777",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        *mounts, "--entrypoint", "/bin/sh", image,
    ]


def run_codeql_scan_isolated(
    source: Path,
    output: Path,
    *,
    image: str,
    query_suites: Mapping[str, str | Path],
    docker_host: str | None = None,
    docker_path: Path | None = None,
) -> dict:
    """Analyze in a pinned, offline container with no host credentials mounted.

    The operator image must contain /opt/codeql/codeql, /bin/sh, and its query packs.
    """
    source, output = Path(source).resolve(), Path(output).resolve()
    if not source.exists() or source == output or source in output.parents or output in source.parents:
        raise CodeQLScanError("CodeQL source and output paths are invalid.")
    if not re.fullmatch(r"[A-Za-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
        raise CodeQLScanError("CodeQL image must be pinned by SHA-256 digest.")
    languages = _detected_languages(source)
    if not languages or not set(languages).issubset(query_suites):
        raise CodeQLScanError("Required CodeQL languages or query suites are unavailable.")
    suites = {language: str(query_suites[language]) for language in languages}
    if any(not suite or "\x00" in suite for suite in suites.values()):
        raise CodeQLScanError("Required CodeQL query suite is invalid.")
    configured_docker = docker_path or shutil.which("docker")
    if not configured_docker:
        raise CodeQLScanError("Docker runtime is not provisioned for isolated CodeQL.")
    docker = _trusted_file(Path(configured_docker), source, output, executable=True)
    host = docker_host or os.environ.get("AEGIS_CODEQL_DOCKER_HOST", "unix:///var/run/docker.sock")
    if not host.startswith("unix://"):
        raise CodeQLScanError("Isolated CodeQL requires a local Docker Unix socket.")
    socket_path = Path(host.removeprefix("unix://")).resolve()
    if source == socket_path or source in socket_path.parents or output == socket_path or output in socket_path.parents:
        raise CodeQLScanError("Docker socket must be outside the scan workspace.")
    try:
        if not stat.S_ISSOCK(socket_path.stat().st_mode):
            raise CodeQLScanError("Local Docker socket is unavailable.")
    except OSError as exc:
        raise CodeQLScanError("Local Docker socket is unavailable.") from exc
    output.mkdir(parents=True, exist_ok=True)
    if any((output / name).exists() for name in ("codeql.sarif", "codeql-report.json")):
        raise CodeQLScanError("CodeQL output artifacts already exist.")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=".codeql-", dir=output) as work:
        workspace = Path(work)
        docker_env = {"PATH": os.defpath, "DOCKER_HOST": host, "DOCKER_CONFIG": work}
        source_root = source
        if source.is_file():
            source_root = workspace / "single-source"
            source_root.mkdir()
            shutil.copy2(source, source_root / source.name)
        all_runs, findings = [], []
        version_name = f"aegis-codeql-{uuid.uuid4().hex}"
        version_command = _docker_base(docker, image, version_name, []) + ["-c", "/opt/codeql/codeql version"]
        try:
            with (workspace / "version.txt").open("wb") as sink:
                version_result = run_bounded_subprocess(version_command, env=docker_env, stdout_sink=sink, timeout=60)
            if version_result.returncode != 0:
                raise CodeQLScanError("Pinned CodeQL image failed preflight.")
            match = re.search(r"\b\d+\.\d+\.\d+\b", (workspace / "version.txt").read_text(errors="replace"))
            if not match:
                raise CodeQLScanError("Pinned CodeQL image has no identifiable CLI version.")
        finally:
            _remove_container(docker, version_name, docker_env)
        for language in languages:
            name = f"aegis-codeql-{uuid.uuid4().hex}"
            sarif = workspace / f"{language}.sarif"
            archive = workspace / f"{language}-source.tar"
            _source_tar(source_root, archive)
            script = (
                "mkdir /work/source; tar -xf /dev/stdin -C /work/source; "
                f"/opt/codeql/codeql database create /work/db --language={language} "
                "--build-mode=none --source-root=/work/source --threads=2 --ram=2048 >/dev/null; "
                f"/opt/codeql/codeql database analyze /work/db {shlex.quote(suites[language])} "
                f"--format=sarifv2.1.0 --sarif-category={language} "
                "--output=/work/report.sarif --threads=2 --ram=2048 >/dev/null; "
                "cat /work/report.sarif"
            )
            command = _docker_base(docker, image, name, ["-i"]) + ["-ec", script]
            try:
                with archive.open("rb") as stdin:
                    completed = run_bounded_subprocess_stdout_to_file(
                        command, output_path=sarif, env=docker_env, stdin=stdin, timeout=600
                    )
                if completed.returncode != 0:
                    raise CodeQLScanError(f"Isolated CodeQL analysis failed for {language}.")
                try:
                    document = load_bounded_json(sarif)
                except FileNotFoundError as exc:
                    raise CodeQLScanError(f"CodeQL analysis produced missing SARIF for {language}.") from exc
                findings.extend(parse_codeql_sarif(sarif, source_root, language=language))
                if len(findings) > resource_budgets().max_scanner_findings:
                    raise CodeQLScanError("CodeQL findings exceed the configured limit.")
                all_runs.extend(document["runs"])
            finally:
                _remove_container(docker, name, docker_env)
        raw = json.dumps({"version": "2.1.0", "runs": all_runs}, separators=(",", ":"), ensure_ascii=False).encode()
        if len(raw) > resource_budgets().max_scanner_report_bytes:
            raise CodeQLScanError("Combined CodeQL SARIF exceeds the configured limit.")
        report = {
            "status": "completed",
            "coverage": {"complete": True, "languages": languages, "source_scope": "file" if source.is_file() else "repository", "isolation": "verified"},
            "tool": {"name": "CodeQL", "version": match.group(), "image": image},
            "query_suites": {language: hashlib.sha256(suites[language].encode()).hexdigest() for language in languages},
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "findings": findings,
        }
        (workspace / "combined.sarif").write_bytes(raw)
        (workspace / "report.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        os.replace(workspace / "combined.sarif", output / "codeql.sarif")
        os.replace(workspace / "report.json", output / "codeql-report.json")
        return report


def _remove_container(docker: Path, name: str, env: dict[str, str]) -> None:
    try:
        run_bounded_subprocess([str(docker), "rm", "-f", name], env=env, timeout=30)
    except (OSError, subprocess.SubprocessError, ResourceLimitError):
        pass
