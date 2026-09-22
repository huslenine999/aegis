import contextlib
import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from policy_engine import run_policy_engine, query_osv_vulnerabilities
from .artifact_storage import artifact_limits, validate_artifact_sizes
from .cli_config import (
    DEFAULT_TOOL_TIMEOUT,
    EXCLUDE_FILES_PATTERN,
    EXIT_ALLOWED,
    EXIT_BLOCKED,
    EXIT_OPERATIONAL_ERROR,
    FAST_MODE_SKIPPED_SCANNERS,
    IGNORED_DIRS,
    PROJECT_ROOT,
    apply_suppressions,
    config_value,
    get_config_section,
    normalize_suppressions,
    resolve_exclude_paths,
    should_skip_path,
    validate_fail_on,
)
from .cli_output import print_ascii_report, print_timing_summary
from .cli_reports import read_json, utc_timestamp, write_json, write_sarif_report
from .config import config_bool, load_advisory_config, load_config
from .dependencies import discover_dependency_manifests, first_requirements_manifest
from .evidence import canonical_json, sign_manifest
from .resource_budgets import (
    ResourceLimitError,
    iter_file_bytes,
    run_bounded_subprocess,
    run_bounded_subprocess_stdout_to_file,
    run_bounded_subprocess_to_file,
)
from .safe_output import SafeOutputRoot
from .sandbox import (
    validate_untrusted_tree,
)
from .scan_engine import (
    CliEventSink,
    ScanEvent,
    ScanRunner,
    add_semgrep_excludes,
    build_ruff_command,
)
from .scan_status import ToolStatusTracker
from .scanners import (
    configure_semgrep_environment,
    find_runtime_executable,
    run_yara_scan as shared_run_yara_scan,
    write_semgrep_rules,
)
from .source_attestation import (
    SourceSnapshot,
    create_source_snapshot,
    normalize_scan_report_paths,
)
from .version import get_package_version


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


def set_fail_on_env(severities: str):
    severity_set = {
        severity.strip().upper()
        for severity in severities.split(",")
        if severity.strip()
    }
    normalized = ",".join(sorted(severity_set))
    if normalized:
        os.environ["FAIL_ON"] = normalized
        os.environ["FAIL_ON_RUFF"] = normalized
        os.environ["FAIL_ON_SEMGREP"] = normalized
        import policy_engine
        policy_engine.FAIL_ON_SEVERITIES = severity_set
        policy_engine.FAIL_ON_RUFF_SEVERITIES = severity_set
        policy_engine.FAIL_ON_SEMGREP_SEVERITIES = severity_set


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


def _cli_evidence_artifacts(scan_dir: Path) -> list[dict]:
    names = {
        "report.html",
        "report.md",
        "aegis.sarif",
        "sbom.json",
        "suppressions-report.json",
        "ruff-report.json",
        "semgrep-report.json",
        "osv-report.json",
        "secrets-report.json",
        "yara-report.json",
        "codeql.sarif",
        "codeql-report.json",
        "source-descriptor.json",
    }
    artifacts = []
    for name in sorted(names):
        path = scan_dir / name
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        size = 0
        for chunk in iter_file_bytes(path, max_bytes=artifact_limits()["per_artifact"]):
            size += len(chunk)
            digest.update(chunk)
        validate_artifact_sizes([(name, size)])
        artifacts.append(
            {
                "name": name,
                "size": size,
                "sha256": digest.hexdigest(),
            }
        )
    return artifacts


def run_scanner_command(
    command,
    *,
    stdout=None,
    output_path: Path | None = None,
    stdout_output_path: Path | None = None,
    accepted_return_codes: set[int] | None = None,
    timeout: int = DEFAULT_TOOL_TIMEOUT,
    label: str = "Scanner",
) -> int:
    try:
        if output_path is not None and stdout_output_path is not None:
            raise ValueError("Choose one scanner output transport.")
        if stdout_output_path is not None:
            result = run_bounded_subprocess_stdout_to_file(
                command,
                stdout_output_path,
                timeout=timeout,
                accepted_return_codes=accepted_return_codes,
            )
        elif output_path is not None:
            result = run_bounded_subprocess_to_file(
                command,
                output_path,
                timeout=timeout,
                accepted_return_codes=accepted_return_codes,
            )
        else:
            result = run_bounded_subprocess(
                command,
                stdout_sink=stdout,
                timeout=timeout,
            )
        return result.returncode
    except ResourceLimitError as exc:
        print(f"  [{label} Warn] Output budget exceeded: {exc}")
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


def _emit_cli_event(event: ScanEvent) -> None:
    if event.event_type != "log":
        return
    text = event.data.get("text")
    if isinstance(text, str):
        level = event.data.get("level", "info")
        log_scanner_event(text, level if isinstance(level, str) else "info")


def execute_scan(
    target_path_str: str,
    *,
    use_docker: bool = True,
    preset: str = "standard",
    enable_yara: bool = False,
    tool_timeout: int | None = DEFAULT_TOOL_TIMEOUT,
    output_dir: str | None = None,
    json_output: bool = False,
    quiet: bool = False,
    fail_on: str | None = None,
    fast: bool = False,
    config_path: str | None = None,
    sarif: str | bool | None = None,
    strict: bool | None = None,
    return_summary: bool = False,
):
    """Admit the source once, then run every scanner against its stable copy."""
    submitted_target = Path(target_path_str).expanduser().absolute()
    if not submitted_target.exists():
        return _execute_scan(
            target_path_str,
            use_docker=use_docker,
            preset=preset,
            enable_yara=enable_yara,
            tool_timeout=tool_timeout,
            output_dir=output_dir,
            json_output=json_output,
            quiet=quiet,
            fail_on=fail_on,
            fast=fast,
            config_path=config_path,
            sarif=sarif,
            strict=strict,
            return_summary=return_summary,
        )
    if config_path and not Path(config_path).expanduser().is_file():
        return _execute_scan(
            target_path_str,
            use_docker=use_docker,
            preset=preset,
            enable_yara=enable_yara,
            tool_timeout=tool_timeout,
            output_dir=output_dir,
            json_output=json_output,
            quiet=quiet,
            fail_on=fail_on,
            fast=fast,
            config_path=config_path,
            sarif=sarif,
            strict=strict,
            return_summary=return_summary,
        )

    source_path = submitted_target.resolve()
    trusted_config = load_config(source_path, config_path)
    configured_excludes = resolve_exclude_paths(trusted_config, source_path)
    snapshot = create_source_snapshot(
        source_path,
        ignored_names=IGNORED_DIRS,
        excluded_paths=configured_excludes,
    )
    try:
        return _execute_scan(
            target_path_str,
            use_docker=use_docker,
            preset=preset,
            enable_yara=enable_yara,
            tool_timeout=tool_timeout,
            output_dir=output_dir,
            json_output=json_output,
            quiet=quiet,
            fail_on=fail_on,
            fast=fast,
            config_path=config_path,
            sarif=sarif,
            strict=strict,
            return_summary=return_summary,
            _source_snapshot=snapshot,
        )
    finally:
        snapshot.cleanup()


def _cli_func(name: str, default):
    cli_mod = sys.modules.get("app.cli")
    if cli_mod and hasattr(cli_mod, name):
        return getattr(cli_mod, name)
    return default


def _execute_scan(
    target_path_str: str,
    *,
    use_docker: bool = True,
    preset: str = "standard",
    enable_yara: bool = False,
    tool_timeout: int | None = DEFAULT_TOOL_TIMEOUT,
    output_dir: str | None = None,
    json_output: bool = False,
    quiet: bool = False,
    fail_on: str | None = None,
    fast: bool = False,
    config_path: str | None = None,
    sarif: str | bool | None = None,
    strict: bool | None = None,
    return_summary: bool = False,
    _source_snapshot: SourceSnapshot | None = None,
):
    timings: list[dict] = []
    total_start = time.perf_counter()
    started_at = utc_timestamp()
    tool_statuses = ToolStatusTracker()
    runner = ScanRunner(CliEventSink(_emit_cli_event), tool_statuses)
    mark_tool = runner.mark_tool

    submitted_target = Path(target_path_str).expanduser().absolute()
    if not submitted_target.exists():
        print(f"❌ Error: Path '{submitted_target}' does not exist.")
        if return_summary:
            return {
                "target": str(submitted_target),
                "exit_code": EXIT_OPERATIONAL_ERROR,
                "status": "error",
                "error": "target_not_found",
            }
        return EXIT_OPERATIONAL_ERROR
    validate_untrusted_tree(submitted_target, ignored_names=IGNORED_DIRS)
    source_path = submitted_target.resolve()
    target_path = source_path
    runner.transition("running", 0)

    if config_path and not Path(config_path).expanduser().is_file():
        raise ValueError(f"Config file does not exist: {Path(config_path).expanduser()}")
    config = load_config(source_path, config_path)
    load_advisory_config(source_path)
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
        if "no_docker" in config or "no_docker" in get_config_section(config):
            raise ValueError("The no_docker option was removed; use scan.preset: quick or --preset quick.")

    if tool_timeout is None:
        tool_timeout = DEFAULT_TOOL_TIMEOUT
    if tool_timeout <= 0:
        raise ValueError("--timeout must be greater than zero.")
    strict = bool(strict)
    if "safety" in config or "safety" in get_config_section(config):
        raise ValueError("The Safety option was removed; OSV provides dependency auditing.")
    if not use_docker:
        raise ValueError("--no-docker was removed; choose --preset quick for a shorter scan.")
    if preset not in {"quick", "standard", "deep"}:
        raise ValueError("--preset must be quick, standard, or deep.")
    if fast:
        if preset != "standard":
            raise ValueError("--fast cannot be combined with --preset; use --preset quick.")
        preset = "quick"
    fast = preset == "quick"
    fail_on = validate_fail_on(fail_on)
    if fail_on:
        set_fail_on_env(str(fail_on))

    configured_excluded_paths = resolve_exclude_paths(config, source_path)
    excluded_paths = (
        _source_snapshot.map_excluded_paths(configured_excluded_paths)
        if _source_snapshot
        else configured_excluded_paths
    )
    suppressions = normalize_suppressions(config, source_path)
    if _source_snapshot:
        target_path = _source_snapshot.scan_path

    print(f"🛡️  Aegis CLI Scanner: Auditing target path: {source_path}")

    dependency_manifests = discover_dependency_manifests(target_path)
    requirements_manifest = first_requirements_manifest(dependency_manifests)
    req_file = requirements_manifest.path if requirements_manifest else None

    if output_dir:
        scan_dir = Path(output_dir).expanduser()
    elif source_path.is_dir():
        scan_dir = source_path / ".aegis" / "scans"
    else:
        scan_dir = source_path.parent / ".aegis" / "scans"
    safe_output = SafeOutputRoot(scan_dir)
    scan_dir = safe_output.root

    placeholder_reports = {
        "ruff-report.json": [],
        "secrets-report.json": {"results": {}},
        "semgrep-report.json": {"results": []},
        "osv-report.json": [],
    }
    for filename, default_data in placeholder_reports.items():
        write_json(scan_dir / filename, default_data, safe_output=safe_output)

    # 1. Dependency analysis (OSV)
    if fast:
        print(f"ℹ️  [Fast Mode] Skipping slower checks: {FAST_MODE_SKIPPED_SCANNERS}.")
        record_timing(timings, "OSV", time.perf_counter(), "skipped")
        mark_tool("OSV", "skipped", detail="fast mode")
    elif dependency_manifests:
        with timed_step(timings, "OSV"):
            manifest_names = ", ".join(sorted({manifest.kind for manifest in dependency_manifests}))
            print(f"🔍 [SCA] Dependency manifest(s) detected: {manifest_names}. Running OSV audit...")
            osv_report_path = safe_output.file("osv-report.json")
            try:
                osv_findings = _cli_func("query_osv_vulnerabilities", query_osv_vulnerabilities)(dependency_manifests, raise_on_error=strict)
                write_json(osv_report_path, osv_findings, safe_output=safe_output)
                print("  [SCA] OSV API checks completed.")
                mark_tool("OSV", "completed")
            except Exception as e:
                print(f"  [SCA Warn] OSV query failed: {e}")
                mark_tool("OSV", "failed", detail=str(e))
    else:
        print("ℹ️  [SCA] No supported dependency manifest found, skipping dependency scan.")
        record_timing(timings, "OSV", time.perf_counter(), "skipped")
        mark_tool("OSV", "skipped", detail="dependency manifest not found")

    # 2. Python SAST (Ruff)
    with timed_step(timings, "Ruff"):
        print("🔍 [SAST] Running Ruff (SAST) code security audits...")
        ruff_report_path = safe_output.file("ruff-report.json")
        ruff_excludes = sorted(IGNORED_DIRS | excluded_paths)
        ruff_cmd = build_ruff_command(sys.executable, str(target_path), ruff_excludes)
        ruff_report_path.unlink(missing_ok=True)
        ruff_return_code = _cli_func("run_scanner_command", run_scanner_command)(
            ruff_cmd,
            stdout_output_path=ruff_report_path,
            accepted_return_codes={0, 1},
            timeout=tool_timeout,
            label="Ruff",
        )
        ruff_report = read_json(ruff_report_path)
        if ruff_return_code in {0, 1} and isinstance(ruff_report, list):
            mark_tool("Ruff", "completed", return_code=ruff_return_code)
        else:
            write_json(ruff_report_path, [], safe_output=safe_output)
            mark_tool(
                "Ruff",
                "failed",
                detail="scanner did not produce a valid report",
                return_code=ruff_return_code,
            )

    # 3. Python SAST (Semgrep)
    print("🔍 [SAST] Running Semgrep rule-based scans...")
    semgrep_report_path = safe_output.file("semgrep-report.json")
    rules_dir = PROJECT_ROOT / "rules"
    rules_dir.mkdir(exist_ok=True)
    semgrep_rules_path = rules_dir / "semgrep_rules.yaml"
    if not semgrep_rules_path.exists():
        write_semgrep_rules(semgrep_rules_path)

    semgrep_bin = find_runtime_executable("semgrep")
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
            semgrep_cmd.append(str(target_path))
            semgrep_report_path.unlink(missing_ok=True)
            semgrep_return_code = _cli_func("run_scanner_command", run_scanner_command)(
                semgrep_cmd,
                stdout_output_path=semgrep_report_path,
                timeout=tool_timeout,
                label="Semgrep",
            )
            semgrep_report = read_json(semgrep_report_path)
            if semgrep_return_code == 0 and isinstance(semgrep_report, dict):
                mark_tool("Semgrep", "completed", return_code=semgrep_return_code)
            else:
                write_json(semgrep_report_path, {"results": []}, safe_output=safe_output)
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
    secrets_report_path = safe_output.file("secrets-report.json")
    secrets_excludes = [
        EXCLUDE_FILES_PATTERN,
        *[re.escape(path) for path in sorted(excluded_paths)],
    ]
    scan_root = source_path if source_path.is_dir() else source_path.parent
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
        secrets_raw_path = safe_output.file("secrets-report.raw.json")
        try:
            with secrets_raw_path.open("w") as f:
                secrets_return_code = _cli_func("run_scanner_command", run_scanner_command)(
                    secrets_cmd,
                    stdout=f,
                    timeout=tool_timeout,
                    label="Secrets",
                )
            secrets_report = read_json(secrets_raw_path)
            if secrets_return_code == 0 and isinstance(secrets_report, dict):
                write_json(secrets_report_path, secrets_report, safe_output=safe_output)
                mark_tool("Secrets", "completed", return_code=secrets_return_code)
            else:
                write_json(secrets_report_path, {"results": {}}, safe_output=safe_output)
                mark_tool(
                    "Secrets",
                    "failed",
                    detail="scanner did not produce a valid report",
                    return_code=secrets_return_code,
                )
        except Exception as e:
            print(f"  [Secrets Error] Failed to run detect-secrets: {e}")
            write_json(secrets_report_path, {"results": {}}, safe_output=safe_output)
            mark_tool("Secrets", "failed", detail=str(e))
        finally:
            secrets_raw_path.unlink(missing_ok=True)

    # Optional signature analysis is enabled only by the CLI operator.
    if enable_yara:
        with timed_step(timings, "YARA"):
            print("🔍 [YARA] Running optional signature analysis...")
            try:
                yara_findings = shared_run_yara_scan(
                    target_path,
                    ignored_paths=set(excluded_paths),
                    log=log_scanner_event,
                )
                safe_output.write_bounded_json("yara-report.json", yara_findings)
                mark_tool("YARA", "completed")
            except Exception as exc:
                print(f"  [YARA Warn] Report was discarded: {exc}")
                mark_tool("YARA", "failed", detail=str(exc))

    # 8. Run Policy Engine
    print("\nEvaluating all reports against Aegis Security Gate rules...")
    html_report = safe_output.file("report.html")
    md_report = safe_output.file("report.md")
    policy_summary = {}
    if _source_snapshot:
        safe_output.write_json("source-descriptor.json", _source_snapshot.descriptor)
        normalize_scan_report_paths(scan_dir, _source_snapshot, safe_output)
    apply_suppressions(scan_dir, suppressions, safe_output=safe_output, read_json_fn=read_json, write_json_fn=write_json)

    def capture_policy_summary(results, final_status, reason, exploitability_score):
        policy_summary.update({
            "policy_status": final_status,
            "reason": reason,
            "exploitability_score": exploitability_score,
            "risk_index": exploitability_score,
            "results": results,
        })
        if not json_output and not quiet:
            print_ascii_report(results, final_status, reason, exploitability_score)
    
    pre_policy_failures = tool_statuses.failures()
    with timed_step(timings, "Policy Engine"):
        policy_exit_code = run_policy_engine(
            scan_dir=scan_dir,
            html_path=html_report,
            md_path=md_report,
            req_path=req_file,
            dependency_manifests=dependency_manifests,
            reporter_callback=capture_policy_summary,
            operational_failures=pre_policy_failures if strict else None,
            tool_states=tool_statuses.states(),
            fail_on_scanner_errors=strict,
            output_root=safe_output,
        )
    record_timing(timings, "Total", total_start)
    mark_tool("Policy Engine", "completed", return_code=policy_exit_code)

    sarif_path = None
    if sarif:
        if isinstance(sarif, str) and sarif not in {"1", "true", "yes", "on"}:
            candidate = Path(sarif)
            sarif_path = safe_output.file_path(candidate)
        else:
            sarif_path = safe_output.file("aegis.sarif")
        sarif_base = source_path if source_path.is_dir() else source_path.parent
        write_sarif_report(
            sarif_path,
            policy_summary.get("results", []),
            base_path=sarif_base,
            safe_output=safe_output,
        )
        policy_summary["sarif_report"] = str(sarif_path)

    failed_tools = tool_statuses.failures()
    exit_code = policy_exit_code
    policy_summary["operational_failures"] = failed_tools
    if strict and failed_tools:
        exit_code = EXIT_OPERATIONAL_ERROR

    policy_contract = {
        "schema_version": 1,
        "fail_on_severities": sorted(
            severity.strip().upper()
            for severity in str(fail_on or "").split(",")
            if severity.strip()
        ),
        "strict": strict,
        "fast": fast,
        "docker_requested": use_docker,
        "safety_enabled": safety_enabled,
        "excluded_paths": sorted(configured_excluded_paths),
        "suppressions": suppressions,
    }
    policy_definition_sha256 = hashlib.sha256(
        canonical_json(policy_contract)
    ).hexdigest()
    if _source_snapshot:
        source_revision = (
            f"sha256:{_source_snapshot.descriptor['files'][0]['sha256']}"
            if _source_snapshot.descriptor["root_kind"] == "file"
            else "local-worktree"
        )
        source_record = _source_snapshot.manifest_source(
            identity=source_path.name,
            revision=source_revision,
            policy_sha256=policy_definition_sha256,
        )
    else:
        source_record = {
            "identity": source_path.name,
            "revision": (
                f"sha256:{hashlib.sha256(source_path.read_bytes()).hexdigest()}"
                if source_path.is_file()
                else "local-worktree"
            ),
        }
    manifest = sign_manifest({
        "schema_version": 3 if _source_snapshot else 2,
        "aegis_version": get_package_version(),
        "target": str(source_path),
        "source": source_record,
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
        "risk_index": policy_summary.get("risk_index", policy_summary.get("exploitability_score", 0.0)),
        "operational_failures": failed_tools,
        "tools": tool_statuses.records,
        "policy_sha256": hashlib.sha256(canonical_json(policy_summary)).hexdigest(),
        "policy_definition_sha256": policy_definition_sha256,
        "artifacts": _cli_evidence_artifacts(scan_dir),
    })
    write_json(scan_dir / "scan-manifest.json", manifest, safe_output=safe_output)
    policy_summary["tools"] = tool_statuses.records

    print(f"\nScan complete. Dossier report available at: {html_report}")
    if not json_output and not quiet:
        print_timing_summary(timings)
    if return_summary:
        return build_scan_summary(source_path, scan_dir, exit_code, policy_summary, timings)
    return exit_code


def install_hook():
    git_dir = Path(".git")
    if not git_dir.exists() or not git_dir.is_dir():
        print("❌ Error: Not a Git repository (no .git directory found).")
        return 1
        
    hook_dir = git_dir / "hooks"
    hook_dir.mkdir(exist_ok=True)
    
    pre_push_path = hook_dir / "pre-push"
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
