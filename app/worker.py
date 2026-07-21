import os
import sys
import uuid
import json
import shutil
import socket
import subprocess
import time
import re
import base64
import hashlib
import queue as thread_queue
import threading
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))
sys.path.append(str(Path(__file__).resolve().parent))

from database import BASE_DIR, PROJECT_ROOT, SCANS_DIR, get_connection, redis_client
from config import environment_positive_int
try:
    from .dependencies import discover_dependency_manifests, first_requirements_manifest
except ImportError:
    from dependencies import (  # type: ignore[no-redef]
        discover_dependency_manifests,
        first_requirements_manifest,
    )
from policy_engine import query_osv_vulnerabilities, run_policy_engine
from scan_status import ToolStatusTracker
from scanners import run_clamav_scan as shared_run_clamav_scan
from scanners import run_dast_scan as shared_run_dast_scan
from scanners import run_yara_scan as shared_run_yara_scan
from scanners import DEFAULT_IGNORED_DIRS
from scanners import configure_semgrep_environment
from scanners import scanner_subprocess_environment
from scanners import write_semgrep_rules
from projects import get_project, get_scan_run, record_scan_artifacts, update_scan_run
from evidence import canonical_json, sign_manifest
from artifact_storage import run_directory
from github_integration import complete_check_run, github_installation_token, github_token
from notifications import queue_project_notification
from sandbox import (
    is_docker_available, scaffold_sandbox_context, build_sandbox_image,
    create_sandbox_network, run_sandbox_container, wait_for_container,
    run_trivy_scan, stop_and_cleanup_sandbox, validate_untrusted_tree
)

EXCLUDE_FILES_PATTERN = rf"(^|/)({'|'.join(re.escape(name) for name in sorted(DEFAULT_IGNORED_DIRS))})(/|$)"
JOB_LOG_LIMIT = environment_positive_int("AEGIS_JOB_LOG_LIMIT", 2000)
JOB_RETENTION_SECONDS = environment_positive_int("AEGIS_JOB_RETENTION_SECONDS", 86400)
ARTIFACT_RETENTION_DAYS = environment_positive_int("AEGIS_ARTIFACT_RETENTION_DAYS", 30)
SCANNER_TIMEOUT_SECONDS = environment_positive_int(
    "AEGIS_SCANNER_TIMEOUT_SECONDS", 300
)
RECORDED_ARTIFACT_NAMES = {
    "report.html",
    "report.md",
    "sbom.json",
    "ruff-report.json",
    "semgrep-report.json",
    "safety-report.json",
    "osv-report.json",
    "trivy-report.json",
    "secrets-report.json",
    "yara-report.json",
    "clamav-report.json",
    "zap-report.json",
    "sandbox-status.json",
    "scan-manifest.json",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_inventory(report_dir: Path) -> list[dict]:
    inventory = []
    for name in sorted(RECORDED_ARTIFACT_NAMES - {"scan-manifest.json"}):
        path = report_dir / name
        if path.is_file():
            inventory.append(
                {
                    "name": name,
                    "size": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    return inventory


def _source_revision(target_path: str | Path) -> str:
    path = Path(target_path)
    working_directory = path if path.is_dir() else path.parent
    git = shutil.which("git")
    if git:
        try:
            result = subprocess.run(
                [git, "rev-parse", "HEAD"],
                cwd=working_directory,
                env=scanner_subprocess_environment(),
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            revision = result.stdout.strip().lower()
            if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", revision):
                return revision
        except (OSError, subprocess.SubprocessError):
            pass
    if path.is_file():
        return f"sha256:{_sha256_file(path)}"
    return "unavailable"


def add_semgrep_excludes(command: list[str]) -> list[str]:
    for ignored_dir in sorted(DEFAULT_IGNORED_DIRS):
        command.extend(["--exclude", ignored_dir])
    return command


def publish_job_event(job_id: str, event_type: str, data: dict):
    channel = f"job_channel:{job_id}"
    payload = {"type": event_type, **data}
    
    if event_type == "state":
        redis_client.hset(f"job:{job_id}", "state", data.get("state", ""))
        redis_client.hset(f"job:{job_id}", "progress", data.get("progress", 0))
    elif event_type == "result":
        redis_client.hset(f"job:{job_id}", "result", json.dumps(data.get("result", {})))
        
    if event_type == "log":
        log_key = f"job_logs:{job_id}"
        redis_client.rpush(log_key, json.dumps(data))
        if hasattr(redis_client, "ltrim"):
            redis_client.ltrim(log_key, -JOB_LOG_LIMIT, -1)
        
    redis_client.publish(channel, json.dumps(payload))
    if event_type == "state" and data.get("state") in {"completed", "failed", "cancelled"}:
        for key in (f"job:{job_id}", f"job_logs:{job_id}"):
            if hasattr(redis_client, "expire"):
                redis_client.expire(key, JOB_RETENTION_SECONDS)

def load_waf_rules_from_db():
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT pattern, description, enabled FROM waf_rules")
        rows = cursor.fetchall()
        rules = []
        for row in rows:
            rules.append({
                "pattern": row[0],
                "description": row[1],
                "enabled": bool(row[2])
            })
        return rules
    except Exception:
        return []
    finally:
        conn.close()


def job_log_callback(job_id: str):
    color_by_level = {
        "error": "var(--danger)",
        "match": "var(--secondary)",
        "muted": "var(--text-muted)",
        "info": "var(--text-muted)",
    }

    def log(message: str, level: str = "info"):
        publish_job_event(
            job_id,
            "log",
            {"text": message, "color": color_by_level.get(level, "var(--text-muted)")},
        )

    return log


def run_yara_scan(target_path: str, job_id: str):
    return shared_run_yara_scan(target_path, log=job_log_callback(job_id))

def run_clamav_scan(target_path: str, job_id: str):
    return shared_run_clamav_scan(target_path, log=job_log_callback(job_id))

def run_dast_scan(
    target_url: str | None = None,
    job_id: str | None = None,
    waf_enabled: bool | None = None,
    *,
    internal_port: int = 5001,
):
    del waf_enabled
    return shared_run_dast_scan(
        target_url,
        internal_port=internal_port,
        log=job_log_callback(job_id) if job_id else None,
    )

def execute_subprocess_log(
    cmd, cwd, job_id, tool_name, env=None, timeout: int = SCANNER_TIMEOUT_SECONDS
):
    publish_job_event(job_id, "log", {"text": f"[{tool_name}] Executing: {' '.join(cmd)}", "color": "var(--text-muted)"})
    try:
        p = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env or scanner_subprocess_environment(),
            start_new_session=os.name != "nt",
        )
        output: thread_queue.Queue[str | None] = thread_queue.Queue()

        def read_output() -> None:
            if p.stdout is not None:
                for line in p.stdout:
                    output.put(line)
            output.put(None)

        threading.Thread(target=read_output, daemon=True).start()
        deadline = time.monotonic() + timeout
        while True:
            _check_cancelled(job_id)
            if time.monotonic() >= deadline:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                publish_job_event(
                    job_id,
                    "log",
                    {
                        "text": f"[{tool_name} Error] Timed out after {timeout}s.",
                        "color": "var(--danger)",
                    },
                )
                return -1
            try:
                line = output.get(timeout=0.25)
            except thread_queue.Empty:
                if p.poll() is not None:
                    break
                continue
            if line is None:
                break
            publish_job_event(job_id, "log", {"text": f"[{tool_name}] {line.strip()}", "color": "var(--text-main)"})
        p.wait(timeout=5)
        return p.returncode
    except ScanCancelled:
        if "p" in locals() and p.poll() is None:
            p.terminate()
        raise
    except Exception as e:
        publish_job_event(job_id, "log", {"text": f"[{tool_name} Error] Failed to run command: {e}", "color": "var(--danger)"})
        return -1

class ScanCancelled(Exception):
    pass


class ScanOperationalFailure(Exception):
    def __init__(self, message: str, result: dict):
        super().__init__(message)
        self.result = result


def _check_cancelled(job_id: str) -> None:
    value = redis_client.hget(f"job:{job_id}", "cancel_requested")
    if value and str(value.decode() if isinstance(value, bytes) else value) == "1":
        raise ScanCancelled()


def _clone_github_project(
    project: dict,
    requested_by: int,
    job_id: str,
    installation_id: int | None = None,
    revision: str | None = None,
) -> tuple[str, Path]:
    destination = SCANS_DIR / "workspaces" / job_id
    destination.parent.mkdir(parents=True, exist_ok=True)
    if revision and not re.fullmatch(r"[0-9a-f]{40,64}", revision):
        raise RuntimeError("GitHub source revision is invalid.")
    token = github_installation_token(installation_id) if installation_id else None
    if not token:
        token = github_token(requested_by)
    if not token and requested_by != project["created_by"]:
        token = github_token(project["created_by"])
    environment = scanner_subprocess_environment()
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            }
        )
    git_executable = shutil.which("git")
    if not git_executable:
        raise RuntimeError("git executable is required to clone GitHub projects")
    clone_command = [git_executable, "clone", "--depth", "1"]
    if revision:
        clone_command.append("--no-checkout")
    else:
        clone_command.extend(["--single-branch", "--branch", project["default_branch"]])
    clone_command.extend(["--", project["repository_url"], str(destination)])
    result = subprocess.run(
        clone_command,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError(f"Repository clone failed: {result.stderr[-500:]}")
    if revision:
        fetch = subprocess.run(
            [git_executable, "-C", str(destination), "fetch", "--depth", "1", "origin", revision],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        checkout = subprocess.run(
            [git_executable, "-C", str(destination), "checkout", "--detach", revision],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if fetch.returncode != 0 or checkout.returncode != 0:
            shutil.rmtree(destination, ignore_errors=True)
            detail = fetch.stderr if fetch.returncode else checkout.stderr
            raise RuntimeError(f"Repository revision checkout failed: {detail[-500:]}")
    return str(destination), destination


def _complete_github_scan_check(
    scan_run_id: int | None,
    project: dict | None,
    conclusion: str,
    summary: str,
    annotations: list[dict] | None = None,
) -> None:
    if not scan_run_id or not project:
        return
    run = get_scan_run(scan_run_id)
    if not run or not all(
        (run.get("github_installation_id"), run.get("github_check_run_id"), project.get("github_full_name"))
    ):
        return
    details_base = os.environ.get("AEGIS_PUBLIC_URL", "").rstrip("/")
    details_url = f"{details_base}/projects" if details_base.startswith("https://") else ""
    try:
        complete_check_run(
            run["github_installation_id"],
            project["github_full_name"],
            run["github_check_run_id"],
            conclusion=conclusion,
            title="Aegis security gate passed" if conclusion == "success" else "Aegis security gate blocked",
            summary=summary,
            details_url=details_url,
            annotations=annotations,
        )
    except Exception as exc:
        publish_job_event(
            run["job_id"],
            "log",
            {"text": f"[GITHUB] Check-run update failed: {str(exc)[:300]}", "color": "var(--warning)"},
        )


def _github_annotation_path(filename: object, target_path: str | Path) -> str | None:
    if not filename:
        return None
    base = Path(target_path).resolve()
    if base.is_file():
        base = base.parent
    candidate = Path(str(filename))
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(base)
        except ValueError:
            return None
    clean = candidate.as_posix().removeprefix("./")
    if not clean or clean == ".." or clean.startswith("../"):
        return None
    return clean[:4096]


def _github_check_annotations(
    result: dict, target_path: str | Path, limit: int = 50
) -> list[dict]:
    """Translate line-addressable scanner findings into GitHub check annotations."""
    annotations: list[dict] = []

    def add(
        filename: object,
        line: object,
        message: object,
        title: object,
        level: str = "warning",
    ) -> None:
        if len(annotations) >= min(max(limit, 0), 50):
            return
        path = _github_annotation_path(filename, target_path)
        if not path:
            return
        try:
            start_line = max(1, int(str(line or 1)))
        except (TypeError, ValueError):
            start_line = 1
        annotations.append({
            "path": path,
            "start_line": start_line,
            "end_line": start_line,
            "annotation_level": level if level in {"notice", "warning", "failure"} else "warning",
            "message": str(message or "Aegis security finding")[:65000],
            "title": str(title or "Aegis finding")[:255],
        })

    for item in result.get("ruff") or []:
        location = item.get("location") or {}
        add(
            item.get("filename"),
            location.get("row"),
            item.get("message"),
            f"Ruff {item.get('code') or 'security finding'}",
        )
    for item in (result.get("semgrep") or {}).get("results", []) or []:
        extra = item.get("extra") or {}
        severity = str(extra.get("severity") or "WARNING").upper()
        add(
            item.get("path"),
            (item.get("start") or {}).get("line"),
            extra.get("message"),
            f"Semgrep {item.get('check_id') or 'security finding'}",
            "failure" if severity == "ERROR" else "warning" if severity == "WARNING" else "notice",
        )
    for filename, items in (result.get("secrets") or {}).get("results", {}).items():
        for item in items or []:
            add(
                filename,
                item.get("line_number"),
                "Potential secret detected. Rotate it if it was ever valid.",
                f"Secret: {item.get('type') or 'credential'}",
                "failure",
            )
    return annotations


def _target_requirements_file(target_path: str | Path) -> Path | None:
    manifest = first_requirements_manifest(discover_dependency_manifests(target_path))
    return manifest.path if manifest else None


def _mirror_latest_reports(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    for path in source_dir.iterdir():
        if not path.is_file():
            continue
        if (
            path.name.endswith("-report.json")
            or path.name in {"osv-report.json", "sandbox-status.json", "report.html", "report.md", "sbom.json"}
        ):
            shutil.copy2(path, SCANS_DIR / path.name)


def _cleanup_expired_artifacts(current_job_id: str) -> None:
    cutoff = time.time() - ARTIFACT_RETENTION_DAYS * 86400
    roots = [SCANS_DIR / "runs"]
    tenant_root = SCANS_DIR / "tenants"
    if tenant_root.is_dir():
        roots.extend(tenant_root.glob("*/projects/*/runs"))
    for runs_root in roots:
        if not runs_root.is_dir():
            continue
        for run_dir in runs_root.iterdir():
            if not run_dir.is_dir() or run_dir.name == current_job_id:
                continue
            try:
                state = redis_client.hget(f"job:{run_dir.name}", "state")
                state_text = state.decode() if isinstance(state, bytes) else str(state or "")
                if state_text and state_text not in {"completed", "failed", "cancelled"}:
                    continue
                if run_dir.stat().st_mtime < cutoff:
                    shutil.rmtree(run_dir, ignore_errors=True)
            except OSError:
                continue


def _finalize_artifacts(scan_run_id: int, report_dir: Path) -> None:
    artifacts = []
    for name in sorted(RECORDED_ARTIFACT_NAMES):
        path = report_dir / name
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                digest.update(chunk)
        artifacts.append(
            {"name": name, "size": path.stat().st_size, "sha256": digest.hexdigest()}
        )
    record_scan_artifacts(scan_run_id, artifacts)


def async_scan_task(
    job_id: str,
    target: str,
    custom_file_path: str | None = None,
    waf_enabled: bool = False,
    scan_run_id: int | None = None,
    project_id: int | None = None,
    requested_by: int | None = None,
    preset: str = "standard",
    source_revision: str | None = None,
    github_installation_id: int | None = None,
):
    external_project_dir = None
    project = get_project(project_id) if project_id else None
    report_dir = run_directory(
        SCANS_DIR,
        job_id,
        tenant_id=project["tenant_id"] if project else None,
        project_id=project_id,
        create=True,
    )
    report_dir.mkdir(parents=True, exist_ok=True)
    _cleanup_expired_artifacts(job_id)
    tool_statuses = ToolStatusTracker()
    mark_tool = tool_statuses.mark

    def write_json(path: Path, value) -> None:
        path.write_text(json.dumps(value, indent=2))

    def load_json_safe(path: Path):
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None

    try:
        python_bin = sys.executable
        is_custom_scan = custom_file_path is not None
        target_path = custom_file_path if is_custom_scan else None
        skip_external_scanners = os.environ.get(
            "AEGIS_SKIP_EXTERNAL_SCANNERS", ""
        ).lower() in {"1", "true", "yes", "on"} or preset == "quick"
        # The explicit scanner skip is used by tests and lightweight smoke
        # environments where Docker may exist but must not be invoked. Deep
        # project scans still fail closed when isolation is unavailable.
        enable_dynamic_scanners = preset == "deep" or (
            scan_run_id is None and not skip_external_scanners
        )
        if (
            preset == "deep"
            and os.environ.get("AEGIS_ENV", "development").lower() == "production"
            and os.environ.get("AEGIS_ALLOW_DEEP_SCANS", "").lower()
            not in {"1", "true", "yes", "on"}
        ):
            raise RuntimeError(
                "Deep scans are disabled in production until an isolated worker is explicitly configured."
            )

        if project_id:
            if not project:
                raise RuntimeError("Project no longer exists.")
            if project["repository_url"]:
                publish_job_event(job_id, "log", {
                    "text": f"[SOURCE] Cloning {project['github_full_name'] or project['repository_url']} at {project['default_branch']}.",
                    "color": "var(--text-muted)",
                })
                target_path, external_project_dir = _clone_github_project(
                    project,
                    requested_by or project["created_by"],
                    job_id,
                    github_installation_id,
                    source_revision,
                )
                target = "project"
        
        # 1. State: QUEUED -> RUNNING
        publish_job_event(job_id, "state", {"state": "running", "progress": 10})
        if scan_run_id:
            update_scan_run(scan_run_id, state="running", progress=10)
        _check_cancelled(job_id)
        publish_job_event(job_id, "log", {"text": f"[SYSTEM] Job claimed by worker. Job ID: {job_id}", "color": "var(--primary)"})
        
        if is_custom_scan:
            if custom_file_path is None:
                raise RuntimeError("Custom scans require a target file path.")
            target_path = custom_file_path
            workspace_limits = validate_untrusted_tree(Path(target_path))
            dependency_manifests = discover_dependency_manifests(target_path)
            # Empty placeholders for custom scans
            with open(report_dir / "safety-report.json", "w") as f:
                json.dump([], f)
            with open(report_dir / "osv-report.json", "w") as f:
                json.dump([], f)
            with open(report_dir / "trivy-report.json", "w") as f:
                json.dump({"Results": []}, f)
            mark_tool("Safety", "skipped", detail="single-file scan")
            mark_tool("OSV", "skipped", detail="single-file scan")
        else:
            if target == "secure":
                target_path = str(BASE_DIR / "secure_main.py")
            elif target == "vulnerable":
                target_path = str(BASE_DIR / "demo_lab.py")
            elif not external_project_dir:
                target_path = str(PROJECT_ROOT)

            if target_path is None:
                raise RuntimeError("Unable to resolve the scan target path.")
            workspace_limits = validate_untrusted_tree(Path(target_path))
            dependency_manifests = discover_dependency_manifests(target_path)
                
            # Run Safety SCA
            safety_enabled = os.environ.get("AEGIS_ENABLE_SAFETY", "").lower() in {
                "1", "true", "yes", "on"
            }
            if skip_external_scanners or not safety_enabled:
                write_json(report_dir / "safety-report.json", [])
                detail = "scanner configuration" if skip_external_scanners else "optional licensed scanner disabled"
                mark_tool("Safety", "skipped", detail=detail)
                publish_job_event(job_id, "log", {"text": f"[SCA] Safety skipped: {detail}.", "color": "var(--text-muted)"})
            else:
                publish_job_event(job_id, "log", {"text": "[SCA] Auditing dependencies via Safety...", "color": "var(--text-muted)"})
                requirements_manifest = first_requirements_manifest(dependency_manifests)
                if requirements_manifest:
                    requirements_file = requirements_manifest.path
                    safety_cmd = [
                        python_bin,
                        "-m",
                        "safety",
                        "scan",
                        "--target",
                        str(requirements_file.parent),
                        "--save-as",
                        "json",
                        str(report_dir / "safety-report.json"),
                    ]
                    safety_environment = scanner_subprocess_environment()
                    if os.environ.get("SAFETY_API_KEY"):
                        safety_environment["SAFETY_API_KEY"] = os.environ["SAFETY_API_KEY"]
                    completed = subprocess.run(
                        safety_cmd,
                        cwd=requirements_file.parent,
                        check=False,
                        timeout=120,
                        env=safety_environment,
                    )
                    safety_report = load_json_safe(report_dir / "safety-report.json")
                    if isinstance(safety_report, (dict, list)):
                        mark_tool("Safety", "completed", return_code=completed.returncode)
                        publish_job_event(job_id, "log", {"text": "[SCA] Safety scan complete.", "color": "var(--primary)"})
                    else:
                        write_json(report_dir / "safety-report.json", [])
                        mark_tool(
                            "Safety",
                            "failed",
                            detail="scanner did not produce a valid JSON report",
                            return_code=completed.returncode,
                        )
                else:
                    write_json(report_dir / "safety-report.json", [])
                    mark_tool("Safety", "skipped", detail="requirements.txt not found")
                    publish_job_event(job_id, "log", {"text": "[SCA] requirements.txt not found in target. Safety skipped.", "color": "var(--text-muted)"})

            if skip_external_scanners:
                write_json(report_dir / "osv-report.json", [])
                mark_tool("OSV", "skipped", detail="scanner configuration")
            elif dependency_manifests:
                try:
                    osv_findings = query_osv_vulnerabilities(
                        dependency_manifests, raise_on_error=True
                    )
                    write_json(report_dir / "osv-report.json", osv_findings)
                    mark_tool("OSV", "completed")
                except Exception as exc:
                    write_json(report_dir / "osv-report.json", [])
                    mark_tool("OSV", "failed", detail=str(exc))
                    publish_job_event(job_id, "log", {"text": f"[OSV Error] {exc}", "color": "var(--danger)"})
            else:
                write_json(report_dir / "osv-report.json", [])
                mark_tool("OSV", "skipped", detail="dependency manifest not found")
            
            # Ensure trivy-report.json exists
            trivy_path = report_dir / "trivy-report.json"
            if not trivy_path.exists():
                with open(trivy_path, "w") as f:
                    json.dump({"Results": []}, f)

        if target_path is None:
            raise RuntimeError("Unable to resolve the scan target path.")

        publish_job_event(
            job_id,
            "log",
            {
                "text": (
                    "[SOURCE] Workspace accepted: "
                    f"{workspace_limits['files']} files, {workspace_limits['bytes']} bytes."
                ),
                "color": "var(--text-muted)",
            },
        )

        # Check Python targets and Docker daemon sandbox
        target_ext = Path(target_path).suffix.lower()
        is_dir = Path(target_path).is_dir()
        has_python = False
        if is_dir:
            for root, dirs, files in os.walk(target_path):
                if any(file.endswith(".py") for file in files):
                    has_python = True
                    break
        else:
            if target_ext == ".py":
                has_python = True

        sandbox_active = False
        sandbox_uuid = uuid.uuid4().hex
        sandbox_image = f"aegis-sandbox-{sandbox_uuid}"
        sandbox_container = f"aegis-sandbox-container-{sandbox_uuid}"
        sandbox_network = f"aegis-sandbox-network-{sandbox_uuid}"
        sandbox_temp_dir = report_dir / "sandbox" / sandbox_uuid
        host_port = None

        def find_free_port() -> int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', 0))
                return s.getsockname()[1]

        docker_available = is_docker_available()
        if enable_dynamic_scanners and docker_available and has_python:
            publish_job_event(job_id, "log", {"text": "[SANDBOX] Docker available. Scaffold target sandbox...", "color": "var(--text-muted)"})
            try:
                host_port = find_free_port()
                container_port = scaffold_sandbox_context(Path(target_path), sandbox_temp_dir)
                publish_job_event(job_id, "log", {"text": f"[SANDBOX] Scaffolding sandbox on port {container_port}", "color": "var(--text-main)"})
                
                if build_sandbox_image(sandbox_temp_dir, sandbox_image):
                    publish_job_event(job_id, "log", {"text": f"[SANDBOX] Built image {sandbox_image}", "color": "var(--primary)"})

                    if not create_sandbox_network(sandbox_network):
                        raise RuntimeError("failed to create isolated sandbox network")

                    if run_sandbox_container(
                        sandbox_image,
                        sandbox_container,
                        host_port,
                        container_port,
                        waf_enabled,
                        sandbox_network,
                    ):
                        publish_job_event(job_id, "log", {"text": f"[SANDBOX] Running container at 127.0.0.1:{host_port}", "color": "var(--primary)"})
                        
                        target_url = f"http://127.0.0.1:{host_port}"
                        if wait_for_container(target_url, timeout=6.0):
                            sandbox_active = True
                            mark_tool("Docker Sandbox", "completed")
                            publish_job_event(job_id, "log", {"text": "[SANDBOX] Container healthy and ready.", "color": "var(--primary)"})
            except Exception as ex:
                mark_tool("Docker Sandbox", "failed", detail=str(ex))
                publish_job_event(job_id, "log", {"text": f"[SANDBOX Error] Failed to launch sandbox: {ex}", "color": "var(--danger)"})
            if not sandbox_active and not tool_statuses.has("Docker Sandbox"):
                mark_tool("Docker Sandbox", "failed", detail="sandbox did not become healthy")
        elif enable_dynamic_scanners:
            reason = "Docker is unavailable" if not docker_available else "no Python target found"
            mark_tool(
                "Docker Sandbox",
                "failed" if scan_run_id else "skipped",
                detail=reason,
            )
        else:
            mark_tool("Docker Sandbox", "skipped", detail="scan preset")

        sandbox_status_file = report_dir / "sandbox-status.json"
        try:
            with open(sandbox_status_file, "w") as sf:
                json.dump({"status": "active" if sandbox_active else "simulated_fallback"}, sf)
        except Exception:
            pass

        # 2. State: RUNNING -> ANALYZING
        publish_job_event(job_id, "state", {"state": "analyzing", "progress": 30})
        if scan_run_id:
            update_scan_run(scan_run_id, state="analyzing", progress=30)
        _check_cancelled(job_id)
        
        # SAST: Ruff (SAST)
        ruff_report_path = report_dir / "ruff-report.json"
        if has_python:
            ruff_cmd = [python_bin, "-m", "ruff", "check", "--no-cache", "--select", "S", "--output-format", "json", "-o", str(ruff_report_path), str(target_path)]
            ruff_cmd.extend(["--exclude", ",".join(sorted(DEFAULT_IGNORED_DIRS))])
            return_code = execute_subprocess_log(ruff_cmd, PROJECT_ROOT, job_id, "SAST:Ruff (SAST)")
            ruff_report = load_json_safe(ruff_report_path)
            if return_code in {0, 1} and isinstance(ruff_report, list):
                mark_tool("Ruff", "completed", return_code=return_code)
            else:
                write_json(ruff_report_path, [])
                mark_tool("Ruff", "failed", detail="scanner did not produce a valid report", return_code=return_code)
        else:
            write_json(ruff_report_path, [])
            mark_tool("Ruff", "skipped", detail="no Python scripts found")
            publish_job_event(job_id, "log", {"text": "[SAST:Ruff (SAST)] Skipped (No Python scripts found)", "color": "var(--text-muted)"})

        # SAST: Semgrep
        semgrep_report_path = report_dir / "semgrep-report.json"
        if has_python and not skip_external_scanners:
            try:
                semgrep_rules_path = PROJECT_ROOT / "rules" / "semgrep_rules.yaml"
                if not semgrep_rules_path.exists():
                    semgrep_rules_path.parent.mkdir(exist_ok=True, parents=True)
                    write_semgrep_rules(semgrep_rules_path)
                
                semgrep_bin = Path(python_bin).parent / "semgrep"
                if not semgrep_bin.exists():
                    semgrep_cmd = ["semgrep", "scan", "--config", str(semgrep_rules_path), "--json"]
                else:
                    semgrep_cmd = [str(semgrep_bin), "scan", "--config", str(semgrep_rules_path), "--json"]
                semgrep_environment = scanner_subprocess_environment()
                configure_semgrep_environment(semgrep_environment)
                semgrep_cmd[2:2] = ["--metrics", "off", "--disable-version-check"]
                add_semgrep_excludes(semgrep_cmd)
                semgrep_cmd.extend(["-o", str(semgrep_report_path), target_path])
                return_code = execute_subprocess_log(
                    semgrep_cmd,
                    PROJECT_ROOT,
                    job_id,
                    "SAST:Semgrep",
                    env=semgrep_environment,
                )
                semgrep_report = load_json_safe(semgrep_report_path)
                if return_code == 0 and isinstance(semgrep_report, dict):
                    mark_tool("Semgrep", "completed", return_code=return_code)
                else:
                    write_json(semgrep_report_path, {"results": []})
                    mark_tool("Semgrep", "failed", detail="scanner did not produce a valid report", return_code=return_code)
            except Exception as exc:
                write_json(semgrep_report_path, {"results": []})
                mark_tool("Semgrep", "failed", detail=str(exc))
        else:
            write_json(semgrep_report_path, {"results": []})
            reason = "scanner configuration" if skip_external_scanners else "no Python scripts found"
            mark_tool("Semgrep", "skipped", detail=reason)
            publish_job_event(job_id, "log", {"text": f"[SAST:Semgrep] Skipped ({reason}).", "color": "var(--text-muted)"})

        # Secrets Scanner
        secrets_report_path = report_dir / "secrets-report.json"
        try:
            if skip_external_scanners:
                write_json(secrets_report_path, {"results": {}})
                mark_tool("Secrets", "skipped", detail="scanner configuration")
                publish_job_event(job_id, "log", {"text": "[Secrets] Skipped by scanner configuration.", "color": "var(--text-muted)"})
            else:
                secrets_cmd = [
                    python_bin, "-m", "detect_secrets", "scan", "--all-files",
                    "--exclude-files", EXCLUDE_FILES_PATTERN,
                    "--no-verify",
                    target_path
                ]
                publish_job_event(job_id, "log", {"text": f"[Secrets] Executing detect-secrets on {target_path}", "color": "var(--text-muted)"})
                with open(secrets_report_path, "w") as report_file:
                    completed = subprocess.run(
                        secrets_cmd,
                        cwd=PROJECT_ROOT,
                        check=False,
                        stdout=report_file,
                        timeout=120,
                        env=scanner_subprocess_environment(),
                    )
                secrets_report = load_json_safe(secrets_report_path)
                if completed.returncode == 0 and isinstance(secrets_report, dict):
                    mark_tool("Secrets", "completed", return_code=completed.returncode)
                    publish_job_event(job_id, "log", {"text": "[Secrets] Scan complete.", "color": "var(--primary)"})
                else:
                    write_json(secrets_report_path, {"results": {}})
                    mark_tool("Secrets", "failed", detail="scanner did not produce a valid report", return_code=completed.returncode)
        except Exception as exc:
            publish_job_event(job_id, "log", {"text": f"[Secrets Error] {exc}", "color": "var(--danger)"})
            write_json(secrets_report_path, {"results": {}})
            mark_tool("Secrets", "failed", detail=str(exc))

        # YARA Scanner
        yara_report_path = report_dir / "yara-report.json"
        try:
            publish_job_event(job_id, "log", {"text": "[YARA] Triggering YARA signature engine...", "color": "var(--text-muted)"})
            yara_findings = run_yara_scan(target_path, job_id)
            with open(yara_report_path, "w") as f:
                json.dump(yara_findings, f, indent=2)
            mark_tool("YARA", "completed")
            publish_job_event(job_id, "log", {"text": "[YARA] Scan complete.", "color": "var(--primary)"})
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[YARA Error] {e}", "color": "var(--danger)"})
            with open(yara_report_path, "w") as f:
                json.dump([], f)
            mark_tool("YARA", "failed", detail=str(e))

        # ClamAV Scanner
        clamav_report_path = report_dir / "clamav-report.json"
        try:
            publish_job_event(job_id, "log", {"text": "[ClamAV] Triggering ClamAV antivirus scanner...", "color": "var(--text-muted)"})
            clamav_findings = run_clamav_scan(target_path, job_id)
            with open(clamav_report_path, "w") as f:
                json.dump(clamav_findings, f, indent=2)
            mark_tool("ClamAV", "completed")
            publish_job_event(job_id, "log", {"text": "[ClamAV] Scan complete.", "color": "var(--primary)"})
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[ClamAV Error] {e}", "color": "var(--danger)"})
            with open(clamav_report_path, "w") as f:
                json.dump([], f)
            mark_tool("ClamAV", "failed", detail=str(e))

        # Aegis DAST Probe Scanner
        zap_report_path = report_dir / "zap-report.json"
        try:
            if not enable_dynamic_scanners:
                zap_findings = []
                mark_tool("DAST", "skipped", detail="scan preset")
            elif sandbox_active:
                publish_job_event(job_id, "log", {"text": "[DAST] Running active probes against the isolated target...", "color": "var(--text-muted)"})
                zap_findings = run_dast_scan(
                    f"http://127.0.0.1:{host_port}",
                    job_id,
                    internal_port=container_port,
                )
                mark_tool("DAST", "completed")
            elif scan_run_id is None:
                zap_findings = []
                mark_tool("DAST", "skipped", detail="isolated target unavailable")
            else:
                zap_findings = []
                mark_tool("DAST", "failed", detail="isolated target was unavailable")
            write_json(zap_report_path, zap_findings)
            publish_job_event(job_id, "log", {"text": "[DAST] DAST scanning complete.", "color": "var(--primary)"})
        except Exception as exc:
            publish_job_event(job_id, "log", {"text": f"[DAST Error] {exc}", "color": "var(--danger)"})
            write_json(zap_report_path, [])
            mark_tool("DAST", "failed", detail=str(exc))

        # Trivy Container Scan
        if sandbox_active:
            publish_job_event(job_id, "log", {"text": "[Trivy] Auditing built image layers for CVEs...", "color": "var(--text-muted)"})
            try:
                run_trivy_scan(sandbox_image, report_dir / "trivy-report.json")
                trivy_report = load_json_safe(report_dir / "trivy-report.json")
                if not isinstance(trivy_report, dict):
                    raise RuntimeError("Trivy did not produce a valid JSON report")
                mark_tool("Trivy", "completed")
                publish_job_event(job_id, "log", {"text": "[Trivy] Image layer audit complete.", "color": "var(--primary)"})
            except Exception as e:
                mark_tool("Trivy", "failed", detail=str(e))
                publish_job_event(job_id, "log", {"text": f"[Trivy Error] {e}", "color": "var(--danger)"})
        elif enable_dynamic_scanners:
            write_json(report_dir / "trivy-report.json", {"Results": []})
            mark_tool(
                "Trivy",
                "failed" if scan_run_id else "skipped",
                detail="isolated container image was unavailable",
            )
        else:
            write_json(report_dir / "trivy-report.json", {"Results": []})
            mark_tool("Trivy", "skipped", detail="scan preset")

        # 3. State: ANALYZING -> CORRELATING
        publish_job_event(job_id, "state", {"state": "correlating", "progress": 70})
        if scan_run_id:
            update_scan_run(scan_run_id, state="correlating", progress=70)
        _check_cancelled(job_id)
        publish_job_event(job_id, "log", {"text": "[SYSTEM] Evaluating scanner outputs against security gate thresholds...", "color": "var(--text-muted)"})
        
        policy_summary = {}

        def capture_policy_summary(results, final_status, reason, exploitability_score):
            policy_summary.update(
                {
                    "results": results,
                    "status": final_status,
                    "reason": reason,
                    "exploitability_score": exploitability_score,
                }
            )

        operational_failures = tool_statuses.failures()
        policy_exit_code = run_policy_engine(
            scan_dir=report_dir,
            html_path=report_dir / "report.html",
            md_path=report_dir / "report.md",
            dependency_manifests=dependency_manifests,
            reporter_callback=capture_policy_summary,
            operational_failures=operational_failures or None,
            tool_states=tool_statuses.states(),
            waf_enabled=waf_enabled,
        )
        mark_tool("Policy Engine", "completed", return_code=policy_exit_code)

        # 4. State: CORRELATING -> REPORTING
        publish_job_event(job_id, "state", {"state": "reporting", "progress": 90})
        if scan_run_id:
            update_scan_run(scan_run_id, state="reporting", progress=90)
        _check_cancelled(job_id)
        publish_job_event(job_id, "log", {"text": "[SYSTEM] Exporting static dossier reports and CycloneDX SBOM...", "color": "var(--text-muted)"})
        time.sleep(1.0) # Visual transition pause

        # Clean up Sandbox Container & Context
        if sandbox_image and sandbox_container:
            try:
                publish_job_event(job_id, "log", {"text": "[SANDBOX] Cleaning up ephemeral Docker sandbox...", "color": "var(--text-muted)"})
                stop_and_cleanup_sandbox(
                    sandbox_container, sandbox_image, sandbox_network
                )
            except Exception as e:
                publish_job_event(job_id, "log", {"text": f"[SANDBOX Cleanup Error] {e}", "color": "var(--danger)"})
        if sandbox_temp_dir and sandbox_temp_dir.exists():
            try:
                shutil.rmtree(sandbox_temp_dir)
            except Exception:
                pass

        if is_custom_scan and target_path and Path(target_path).parent.exists():
            try:
                shutil.rmtree(Path(target_path).parent)
            except Exception:
                pass

        raw_results = {
            "ruff": load_json_safe(report_dir / "ruff-report.json"),
            "semgrep": load_json_safe(report_dir / "semgrep-report.json"),
            "safety": load_json_safe(report_dir / "safety-report.json"),
            "osv": load_json_safe(report_dir / "osv-report.json"),
            "trivy": load_json_safe(report_dir / "trivy-report.json"),
            "secrets": load_json_safe(report_dir / "secrets-report.json"),
            "yara": load_json_safe(report_dir / "yara-report.json"),
            "clamav": load_json_safe(report_dir / "clamav-report.json"),
            "zap": load_json_safe(report_dir / "zap-report.json"),
        }
        final_status = policy_summary.get("status", "ERROR")
        blocking_tools = [
            result["tool"]
            for result in policy_summary.get("results", [])
            if result.get("status") == "FAIL"
        ]
        result_payload = {
            **raw_results,
            "policy": policy_summary,
            "tools": [dict(item) for item in tool_statuses.records],
            "operational_failures": operational_failures,
            "exploitability_score": policy_summary.get("exploitability_score", 0.0),
            "waf_enabled": waf_enabled,
            "has_run": True,
            "is_blocked": final_status == "BLOCKED",
            "blocked_by": blocking_tools,
            "sandbox_status": "active" if sandbox_active else "unavailable",
            "artifact_base": f"/api/projects/{project_id}/scans/{scan_run_id}/artifacts" if project_id and scan_run_id else None,
        }
        policy_digest = hashlib.sha256(canonical_json(policy_summary)).hexdigest()
        target_identity = (
            project["github_full_name"] or project["repository_url"]
            if project
            else "uploaded-file" if is_custom_scan else str(target)
        )
        write_json(
            report_dir / "scan-manifest.json",
            sign_manifest({
                "schema_version": 2,
                "job_id": job_id,
                "project_id": project_id,
                "scan_run_id": scan_run_id,
                "tenant_id": project["tenant_id"] if project else None,
                "source": {
                    "identity": target_identity,
                    "revision": _source_revision(target_path),
                    "branch": project["default_branch"] if project else None,
                },
                "preset": preset,
                "policy_status": final_status,
                "policy_exit_code": policy_exit_code,
                "policy_sha256": policy_digest,
                "operational_failures": operational_failures,
                "tools": [dict(item) for item in tool_statuses.records],
                "artifacts": _artifact_inventory(report_dir),
            }),
        )

        if scan_run_id is None:
            _mirror_latest_reports(report_dir)
        else:
            _finalize_artifacts(scan_run_id, report_dir)

        if final_status == "ERROR":
            raise ScanOperationalFailure(policy_summary.get("reason", "Scanner operational failure"), result_payload)

        # 5. State: REPORTING -> COMPLETED
        if scan_run_id:
            update_scan_run(
                scan_run_id, state="completed", progress=100, result=result_payload
            )
        _complete_github_scan_check(
            scan_run_id,
            project,
            "failure" if result_payload["is_blocked"] else "success",
            (
                f"Policy status: {final_status}. New findings: "
                f"{result_payload.get('new_findings', 0)}. Blocking tools: "
                f"{', '.join(blocking_tools) or 'none'}."
            ),
            _github_check_annotations(result_payload, target_path),
        )
        if project_id:
            project = get_project(project_id)
            queue_project_notification(
                project_id,
                "blocked" if result_payload["is_blocked"] else "completed",
                {
                    "project_name": project["name"] if project else "Project",
                    "job_id": job_id,
                    "new_findings": result_payload.get("new_findings", 0),
                    "is_blocked": result_payload["is_blocked"],
                    "blocked_by": blocking_tools,
                },
            )
        publish_job_event(job_id, "result", {"result": result_payload})
        publish_job_event(job_id, "state", {"state": "completed", "progress": 100})
        publish_job_event(job_id, "log", {"text": "[OK] GATE VERDICT READY: Scan execution completed successfully.", "color": "var(--primary)"})
        
    except ScanCancelled:
        if scan_run_id:
            update_scan_run(scan_run_id, state="cancelled", progress=100)
        _complete_github_scan_check(scan_run_id, project, "cancelled", "The Aegis scan was cancelled.")
        publish_job_event(job_id, "state", {"state": "cancelled", "progress": 100})
        publish_job_event(job_id, "log", {"text": "[SYSTEM] Scan cancelled by user.", "color": "var(--secondary)"})
        if project_id:
            project = get_project(project_id)
            queue_project_notification(project_id, "cancelled", {
                "project_name": project["name"] if project else "Project",
                "job_id": job_id,
            })
    except ScanOperationalFailure as exc:
        if scan_run_id:
            update_scan_run(scan_run_id, state="failed", progress=100, result=exc.result)
        _complete_github_scan_check(scan_run_id, project, "failure", f"Scanner evidence was incomplete: {str(exc)[:500]}")
        publish_job_event(job_id, "result", {"result": exc.result})
        publish_job_event(job_id, "state", {"state": "failed", "progress": 100})
        publish_job_event(job_id, "log", {"text": f"[ERROR] Security evidence is incomplete: {exc}", "color": "var(--danger)"})
        redis_client.hset(f"job:{job_id}", "error", str(exc))
        if project_id:
            project = get_project(project_id)
            queue_project_notification(project_id, "failed", {
                "project_name": project["name"] if project else "Project",
                "job_id": job_id,
                "error": str(exc)[:500],
            })
        raise
    except Exception as e:
        if scan_run_id:
            update_scan_run(scan_run_id, state="failed", progress=100)
        _complete_github_scan_check(scan_run_id, project, "failure", f"Scan execution failed: {str(e)[:500]}")
        publish_job_event(job_id, "state", {"state": "failed", "progress": 100})
        publish_job_event(job_id, "log", {"text": f"[FATAL] Scan job execution failed: {e}", "color": "var(--danger)"})
        redis_client.hset(f"job:{job_id}", "error", str(e))
        if project_id:
            project = get_project(project_id)
            queue_project_notification(project_id, "failed", {
                "project_name": project["name"] if project else "Project",
                "job_id": job_id,
                "error": str(e)[:500],
            })
        raise e
    finally:
        if external_project_dir:
            shutil.rmtree(external_project_dir, ignore_errors=True)
