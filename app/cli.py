import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

# Re-export scanner & sandbox primitives for backward compatibility and test patching
from policy_engine import query_osv_vulnerabilities, run_policy_engine
from .sandbox import (
    build_sandbox_image,
    create_sandbox_network,
    is_docker_available,
    run_sandbox_container,
    run_trivy_scan,
    scaffold_sandbox_context,
    stop_and_cleanup_sandbox,
    wait_for_container,
)
from .scanners import (
    run_clamav_scan as shared_run_clamav_scan,
    run_dast_scan as shared_run_dast_scan,
    run_yara_scan as shared_run_yara_scan,
)

# Re-export configuration & suppression primitives
from .cli_config import (
    DEFAULT_SCAN_DIR,
    DEFAULT_TOOL_TIMEOUT,
    EXCLUDE_FILES_PATTERN,
    EXIT_ALLOWED,
    EXIT_BLOCKED,
    EXIT_OPERATIONAL_ERROR,
    FAST_MODE_SKIPPED_SCANNERS,
    IGNORED_DIRS,
    LOCAL_ENV_FILE,
    PROJECT_ROOT,
    VALID_SEVERITIES,
    apply_suppressions,
    config_value,
    get_config_base,
    get_config_section,
    is_excluded_path,
    normalize_suppressions,
    resolve_exclude_paths,
    should_skip_path,
    suppression_matches,
    validate_fail_on,
)

# Re-export output formatting
from .cli_output import (
    format_cell,
    format_duration,
    print_ascii_report,
    print_timing_summary,
)

# Re-export reporting & verification helpers
from .cli_reports import (
    create_demo_target,
    find_report_file,
    hmac_compare_digest,
    open_report_file,
    read_json,
    run_doctor,
    run_report,
    run_verify_evidence,
    utc_timestamp,
    write_json,
    write_sarif_report,
)
from .cli_reports import (
    run_demo as _cli_reports_run_demo,
)

# Re-export runner & execution pipeline
from .cli_runner import (
    _cli_evidence_artifacts,
    _emit_cli_event,
    _execute_scan,
    build_scan_summary,
    execute_scan,
    find_free_host_port,
    install_hook,
    log_scanner_event,
    record_timing,
    run_dast_scan,
    run_scanner_command,
    set_fail_on_env,
    timed_step,
    uninstall_hook,
)

# Re-export stack management
from . import cli_stack
from .version import get_package_version

__all__ = [
    "DEFAULT_SCAN_DIR",
    "DEFAULT_TOOL_TIMEOUT",
    "EXCLUDE_FILES_PATTERN",
    "EXIT_ALLOWED",
    "EXIT_BLOCKED",
    "EXIT_OPERATIONAL_ERROR",
    "FAST_MODE_SKIPPED_SCANNERS",
    "IGNORED_DIRS",
    "LOCAL_ENV_FILE",
    "PROJECT_ROOT",
    "VALID_SEVERITIES",
    "_cli_evidence_artifacts",
    "_docker_compose_command",
    "_emit_cli_event",
    "_execute_scan",
    "_local_environment_values",
    "_port_is_available",
    "_read_environment_file",
    "_require_local_stack",
    "_wait_for_dashboard",
    "_write_environment_file",
    "apply_suppressions",
    "build_sandbox_image",
    "build_scan_summary",
    "config_value",
    "create_demo_target",
    "create_sandbox_network",
    "execute_scan",
    "find_free_host_port",
    "find_report_file",
    "format_cell",
    "format_duration",
    "get_config_base",
    "get_config_section",
    "hmac_compare_digest",
    "install_hook",
    "is_docker_available",
    "is_excluded_path",
    "log_scanner_event",
    "main",
    "normalize_suppressions",
    "open_report_file",
    "print_ascii_report",
    "print_timing_summary",
    "query_osv_vulnerabilities",
    "read_json",
    "record_timing",
    "resolve_exclude_paths",
    "run_backup",
    "run_dast_scan",
    "run_demo",
    "run_doctor",
    "run_policy_engine",
    "run_report",
    "run_restore",
    "run_sandbox_container",
    "run_scanner_command",
    "run_stack_logs",
    "run_start",
    "run_stop",
    "run_trivy_scan",
    "run_upgrade",
    "run_verify_evidence",
    "scaffold_sandbox_context",
    "set_fail_on_env",
    "shared_run_clamav_scan",
    "shared_run_dast_scan",
    "shared_run_yara_scan",
    "should_skip_path",
    "stop_and_cleanup_sandbox",
    "suppression_matches",
    "timed_step",
    "uninstall_hook",
    "utc_timestamp",
    "validate_fail_on",
    "wait_for_container",
    "write_json",
    "write_sarif_report",
]


def run_demo(*, open_report: bool = False, output_dir: str | None = None) -> int:
    return _cli_reports_run_demo(
        execute_scan_fn=execute_scan,
        open_report=open_report,
        output_dir=output_dir,
    )


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


def main():
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
    scan_parser.add_argument(
        "--config",
        help="Explicit operator-selected trusted aegis.yml config file",
    )
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
    evidence_parser = subparsers.add_parser(
        "verify-evidence", help="Verify a signed scan manifest and its artifacts"
    )
    evidence_parser.add_argument("manifest", help="Path to scan-manifest.json")
    evidence_parser.add_argument(
        "--public-key",
        help="Pinned URL-safe base64 Ed25519 public key (recommended)",
    )
    evidence_parser.add_argument(
        "--trust-embedded-key",
        action="store_true",
        help="Trust the manifest's embedded key (local integrity check only)",
    )
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
    elif args.command == "verify-evidence":
        return run_verify_evidence(
            args.manifest,
            args.public_key,
            trust_embedded_key=args.trust_embedded_key,
        )
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
