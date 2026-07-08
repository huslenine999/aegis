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
from pathlib import Path
import redis

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))
sys.path.append(str(Path(__file__).resolve().parent))

from database import BASE_DIR, PROJECT_ROOT, DOWNLOAD_DIR, SCANS_DIR, get_connection, redis_client
from config import environment_positive_int
try:
    from .dependencies import discover_dependency_manifests, first_requirements_manifest
except ImportError:
    from dependencies import discover_dependency_manifests, first_requirements_manifest
from policy_engine import get_ruff_severity
from scanners import run_clamav_scan as shared_run_clamav_scan
from scanners import run_yara_scan as shared_run_yara_scan
from scanners import DEFAULT_IGNORED_DIRS
from scanners import configure_semgrep_environment
from scanners import write_semgrep_rules
from projects import get_project, update_scan_run
from github_integration import github_token
from notifications import send_project_notification
from sandbox import (
    is_docker_available, scaffold_sandbox_context, build_sandbox_image,
    run_sandbox_container, wait_for_container, run_trivy_scan, stop_and_cleanup_sandbox,
    get_active_sandbox_container, get_sandbox_stats, get_sandbox_logs
)

EXCLUDE_FILES_PATTERN = rf"(^|/)({'|'.join(re.escape(name) for name in sorted(DEFAULT_IGNORED_DIRS))})(/|$)"
JOB_LOG_LIMIT = environment_positive_int("AEGIS_JOB_LOG_LIMIT", 2000)
JOB_RETENTION_SECONDS = environment_positive_int("AEGIS_JOB_RETENTION_SECONDS", 86400)


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

def run_dast_scan(target_url: str = None, job_id: str = None, waf_enabled: bool = None):
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
            publish_job_event(job_id, "log", {"text": f"[DAST] Scanning route: {tc['route']} with payload: {tc['payload']}", "color": "var(--text-muted)"})
            try:
                res = requests.get(url, params=tc["params"], timeout=3)
                status_code = res.status_code
            except Exception as e:
                status_code = 500
            
            status = "MITIGATED" if status_code == 403 else "EXPOSED"
            color = "var(--primary)" if status_code == 403 else "var(--danger)"
            publish_job_event(job_id, "log", {"text": f"[DAST] Result for {tc['vuln_type']}: {status} (HTTP {status_code})", "color": color})
            
            findings.append({
                "vuln_type": tc["vuln_type"],
                "route": tc["route"],
                "payload": tc["payload"],
                "description": tc["description"],
                "status": status,
                "response_code": status_code
            })
    else:
        # If no sandbox container is running, execute local requests directly against app via TestClient
        from fastapi.testclient import TestClient
        import app.main as app_main
        
        # Override WAF_ENABLED in target process space if provided
        old_waf = app_main.WAF_ENABLED
        if waf_enabled is not None:
            app_main.WAF_ENABLED = waf_enabled
            
        try:
            client = TestClient(app_main.app)
            for tc in test_cases:
                publish_job_event(job_id, "log", {"text": f"[DAST Fallback] Querying {tc['route']}...", "color": "var(--text-muted)"})
                try:
                    res = client.get(tc["route"], params=tc["params"])
                    status_code = res.status_code
                except Exception as e:
                    status_code = 500
                
                status = "MITIGATED" if status_code == 403 else "EXPOSED"
                color = "var(--primary)" if status_code == 403 else "var(--danger)"
                publish_job_event(job_id, "log", {"text": f"[DAST Fallback] Result for {tc['vuln_type']}: {status} (HTTP {status_code})", "color": color})
                
                findings.append({
                    "vuln_type": tc["vuln_type"],
                    "route": tc["route"],
                    "payload": tc["payload"],
                    "description": tc["description"],
                    "status": status,
                    "response_code": status_code
                })
        finally:
            if waf_enabled is not None:
                app_main.WAF_ENABLED = old_waf
    return findings

def execute_subprocess_log(cmd, cwd, job_id, tool_name, env=None):
    publish_job_event(job_id, "log", {"text": f"[{tool_name}] Executing: {' '.join(cmd)}", "color": "var(--text-muted)"})
    try:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        for line in p.stdout:
            publish_job_event(job_id, "log", {"text": f"[{tool_name}] {line.strip()}", "color": "var(--text-main)"})
        p.wait()
        return p.returncode
    except Exception as e:
        publish_job_event(job_id, "log", {"text": f"[{tool_name} Error] Failed to run command: {e}", "color": "var(--danger)"})
        return -1

class ScanCancelled(Exception):
    pass


def _check_cancelled(job_id: str) -> None:
    value = redis_client.hget(f"job:{job_id}", "cancel_requested")
    if value and str(value.decode() if isinstance(value, bytes) else value) == "1":
        raise ScanCancelled()


def _clone_github_project(project: dict, requested_by: int, job_id: str) -> tuple[str, Path]:
    destination = SCANS_DIR / "workspaces" / job_id
    destination.parent.mkdir(parents=True, exist_ok=True)
    token = github_token(requested_by)
    environment = os.environ.copy()
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
            }
        )
    result = subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--branch",
            project["default_branch"],
            "--",
            project["repository_url"],
            str(destination),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        shutil.rmtree(destination, ignore_errors=True)
        raise RuntimeError(f"Repository clone failed: {result.stderr[-500:]}")
    return str(destination), destination


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


def async_scan_task(
    job_id: str,
    target: str,
    custom_file_path: str = None,
    waf_enabled: bool = False,
    scan_run_id: int = None,
    project_id: int = None,
    requested_by: int = None,
    preset: str = "standard",
):
    external_project_dir = None
    report_dir = SCANS_DIR / "runs" / job_id
    report_dir.mkdir(parents=True, exist_ok=True)
    try:
        python_bin = sys.executable
        is_custom_scan = custom_file_path is not None
        target_path = custom_file_path if is_custom_scan else None
        skip_external_scanners = os.environ.get(
            "AEGIS_SKIP_EXTERNAL_SCANNERS", ""
        ).lower() in {"1", "true", "yes", "on"} or preset == "quick"
        enable_dynamic_scanners = scan_run_id is None or preset == "deep"

        if project_id:
            project = get_project(project_id)
            if not project:
                raise RuntimeError("Project no longer exists.")
            if project["repository_url"]:
                publish_job_event(job_id, "log", {
                    "text": f"[SOURCE] Cloning {project['github_full_name'] or project['repository_url']} at {project['default_branch']}.",
                    "color": "var(--text-muted)",
                })
                target_path, external_project_dir = _clone_github_project(
                    project, project["created_by"], job_id
                )
                target = "project"
        
        # 1. State: QUEUED -> RUNNING
        publish_job_event(job_id, "state", {"state": "running", "progress": 10})
        if scan_run_id:
            update_scan_run(scan_run_id, state="running", progress=10)
        _check_cancelled(job_id)
        publish_job_event(job_id, "log", {"text": f"[SYSTEM] Job claimed by worker. Job ID: {job_id}", "color": "var(--primary)"})
        
        if is_custom_scan:
            target_path = custom_file_path
            dependency_manifests = discover_dependency_manifests(target_path)
            # Empty placeholders for custom scans
            with open(report_dir / "safety-report.json", "w") as f:
                json.dump([], f)
            with open(report_dir / "osv-report.json", "w") as f:
                json.dump([], f)
            with open(report_dir / "trivy-report.json", "w") as f:
                json.dump({"Results": []}, f)
        else:
            if target == "secure":
                target_path = str(BASE_DIR / "secure_main.py")
            elif target == "vulnerable":
                target_path = str(BASE_DIR / "demo_lab.py")
            elif not external_project_dir:
                target_path = str(PROJECT_ROOT)

            dependency_manifests = discover_dependency_manifests(target_path)
                
            # Run Safety SCA
            if skip_external_scanners:
                with open(report_dir / "safety-report.json", "w") as f:
                    json.dump([], f)
                publish_job_event(job_id, "log", {"text": "[SCA] Safety skipped by scanner configuration.", "color": "var(--text-muted)"})
            else:
                publish_job_event(job_id, "log", {"text": "[SCA] Auditing dependencies via Safety...", "color": "var(--text-muted)"})
                requirements_manifest = first_requirements_manifest(dependency_manifests)
                if requirements_manifest:
                    requirements_file = requirements_manifest.path
                    safety_cmd = [python_bin, "-m", "safety", "check", "-r", str(requirements_file), "--save-json", str(report_dir / "safety-report.json")]
                    subprocess.run(safety_cmd, cwd=requirements_file.parent, check=False)
                    publish_job_event(job_id, "log", {"text": "[SCA] Safety scan complete.", "color": "var(--primary)"})
                else:
                    with open(report_dir / "safety-report.json", "w") as f:
                        json.dump([], f)
                    publish_job_event(job_id, "log", {"text": "[SCA] requirements.txt not found in target. Safety skipped.", "color": "var(--text-muted)"})
            
            # Ensure trivy-report.json exists
            trivy_path = report_dir / "trivy-report.json"
            if not trivy_path.exists():
                with open(trivy_path, "w") as f:
                    json.dump({"Results": []}, f)

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
        sandbox_temp_dir = report_dir / "sandbox" / sandbox_uuid
        host_port = None

        def find_free_port() -> int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', 0))
                return s.getsockname()[1]

        if enable_dynamic_scanners and is_docker_available() and has_python:
            publish_job_event(job_id, "log", {"text": "[SANDBOX] Docker available. Scaffold target sandbox...", "color": "var(--text-muted)"})
            try:
                host_port = find_free_port()
                container_port = scaffold_sandbox_context(Path(target_path), sandbox_temp_dir)
                publish_job_event(job_id, "log", {"text": f"[SANDBOX] Scaffolding sandbox on port {container_port}", "color": "var(--text-main)"})
                
                if build_sandbox_image(sandbox_temp_dir, sandbox_image):
                    publish_job_event(job_id, "log", {"text": f"[SANDBOX] Built image {sandbox_image}", "color": "var(--primary)"})
                    
                    if run_sandbox_container(sandbox_image, sandbox_container, host_port, container_port, waf_enabled):
                        publish_job_event(job_id, "log", {"text": f"[SANDBOX] Running container at 127.0.0.1:{host_port}", "color": "var(--primary)"})
                        
                        target_url = f"http://127.0.0.1:{host_port}"
                        if wait_for_container(target_url, timeout=6.0):
                            sandbox_active = True
                            publish_job_event(job_id, "log", {"text": "[SANDBOX] Container healthy and ready.", "color": "var(--primary)"})
            except Exception as ex:
                publish_job_event(job_id, "log", {"text": f"[SANDBOX Error] Failed to launch sandbox: {ex}", "color": "var(--danger)"})

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
            ruff_cmd = [python_bin, "-m", "ruff", "check", "--select", "S", "--output-format", "json", "-o", str(ruff_report_path), str(target_path)]
            ruff_cmd.extend(["--exclude", ",".join(sorted(DEFAULT_IGNORED_DIRS))])
            execute_subprocess_log(ruff_cmd, PROJECT_ROOT, job_id, "SAST:Ruff (SAST)")
        else:
            with open(ruff_report_path, "w") as f:
                json.dump([], f)
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
                configure_semgrep_environment()
                semgrep_cmd[2:2] = ["--metrics", "off", "--disable-version-check"]
                add_semgrep_excludes(semgrep_cmd)
                semgrep_cmd.extend(["-o", str(semgrep_report_path), target_path])
                execute_subprocess_log(semgrep_cmd, PROJECT_ROOT, job_id, "SAST:Semgrep")
            except Exception as e:
                with open(semgrep_report_path, "w") as f:
                    json.dump({"results": []}, f)
        else:
            with open(semgrep_report_path, "w") as f:
                json.dump({"results": []}, f)
            reason = "scanner configuration" if skip_external_scanners else "no Python scripts found"
            publish_job_event(job_id, "log", {"text": f"[SAST:Semgrep] Skipped ({reason}).", "color": "var(--text-muted)"})

        # Secrets Scanner
        secrets_report_path = report_dir / "secrets-report.json"
        try:
            if skip_external_scanners:
                with open(secrets_report_path, "w") as f:
                    json.dump({"results": {}}, f)
                publish_job_event(job_id, "log", {"text": "[Secrets] Skipped by scanner configuration.", "color": "var(--text-muted)"})
            else:
                secrets_cmd = [
                    python_bin, "-m", "detect_secrets", "scan", "--all-files",
                    "--exclude-files", EXCLUDE_FILES_PATTERN,
                    "--no-verify",
                    target_path
                ]
                publish_job_event(job_id, "log", {"text": f"[Secrets] Executing detect-secrets on {target_path}", "color": "var(--text-muted)"})
                with open(secrets_report_path, "w") as f:
                    subprocess.run(secrets_cmd, cwd=PROJECT_ROOT, check=False, stdout=f)
                publish_job_event(job_id, "log", {"text": "[Secrets] Scan complete.", "color": "var(--primary)"})
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[Secrets Error] {e}", "color": "var(--danger)"})
            with open(secrets_report_path, "w") as f:
                json.dump({"results": {}}, f)

        # YARA Scanner
        yara_report_path = report_dir / "yara-report.json"
        try:
            publish_job_event(job_id, "log", {"text": "[YARA] Triggering YARA signature engine...", "color": "var(--text-muted)"})
            yara_findings = run_yara_scan(target_path, job_id)
            with open(yara_report_path, "w") as f:
                json.dump(yara_findings, f, indent=2)
            publish_job_event(job_id, "log", {"text": "[YARA] Scan complete.", "color": "var(--primary)"})
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[YARA Error] {e}", "color": "var(--danger)"})
            with open(yara_report_path, "w") as f:
                json.dump([], f)

        # ClamAV Scanner
        clamav_report_path = report_dir / "clamav-report.json"
        try:
            publish_job_event(job_id, "log", {"text": "[ClamAV] Triggering ClamAV antivirus scanner...", "color": "var(--text-muted)"})
            clamav_findings = run_clamav_scan(target_path, job_id)
            with open(clamav_report_path, "w") as f:
                json.dump(clamav_findings, f, indent=2)
            publish_job_event(job_id, "log", {"text": "[ClamAV] Scan complete.", "color": "var(--primary)"})
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[ClamAV Error] {e}", "color": "var(--danger)"})
            with open(clamav_report_path, "w") as f:
                json.dump([], f)

        # Aegis DAST Probe Scanner
        zap_report_path = report_dir / "zap-report.json"
        try:
            publish_job_event(job_id, "log", {"text": "[DAST] Running active crawler against endpoints...", "color": "var(--text-muted)"})
            if not enable_dynamic_scanners:
                zap_findings = []
            elif sandbox_active:
                zap_findings = run_dast_scan(f"http://127.0.0.1:{host_port}", job_id)
            else:
                if is_custom_scan or target == "secure":
                    zap_findings = []
                else:
                    zap_findings = run_dast_scan(None, job_id)
            with open(zap_report_path, "w") as f:
                json.dump(zap_findings, f, indent=2)
            publish_job_event(job_id, "log", {"text": "[DAST] DAST scanning complete.", "color": "var(--primary)"})
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[DAST Error] {e}", "color": "var(--danger)"})
            with open(zap_report_path, "w") as f:
                json.dump([], f)

        # Trivy Container Scan
        if sandbox_active:
            publish_job_event(job_id, "log", {"text": "[Trivy] Auditing built image layers for CVEs...", "color": "var(--text-muted)"})
            try:
                run_trivy_scan(sandbox_image, report_dir / "trivy-report.json")
                publish_job_event(job_id, "log", {"text": "[Trivy] Image layer audit complete.", "color": "var(--primary)"})
            except Exception as e:
                publish_job_event(job_id, "log", {"text": f"[Trivy Error] {e}", "color": "var(--danger)"})

        # 3. State: ANALYZING -> CORRELATING
        publish_job_event(job_id, "state", {"state": "correlating", "progress": 70})
        if scan_run_id:
            update_scan_run(scan_run_id, state="correlating", progress=70)
        _check_cancelled(job_id)
        publish_job_event(job_id, "log", {"text": "[SYSTEM] Evaluating scanner outputs against security gate thresholds...", "color": "var(--text-muted)"})
        
        # Run policy engine
        engine_path = PROJECT_ROOT / "policy_engine.py"
        engine_cmd = [python_bin, str(engine_path)]
        engine_env = os.environ.copy()
        engine_env["SCANS_DIR"] = str(report_dir)
        engine_env["AEGIS_TARGET_PATH"] = str(target_path)
        execute_subprocess_log(engine_cmd, PROJECT_ROOT, job_id, "PolicyEngine", env=engine_env)

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
                stop_and_cleanup_sandbox(sandbox_container, sandbox_image)
            except Exception as e:
                publish_job_event(job_id, "log", {"text": f"[SANDBOX Cleanup Error] {e}", "color": "var(--danger)"})
        if sandbox_temp_dir and sandbox_temp_dir.exists():
            try:
                shutil.rmtree(sandbox_temp_dir)
            except Exception as e:
                pass

        if is_custom_scan and target_path and Path(target_path).parent.exists():
            try:
                shutil.rmtree(Path(target_path).parent)
            except Exception:
                pass

        # Load scan results to save to Job Hash
        def load_json_safe(path):
            if path.exists():
                try:
                    return json.loads(path.read_text())
                except Exception:
                    pass
            return None
            
        clamav = load_json_safe(report_dir / "clamav-report.json")
        zap = load_json_safe(report_dir / "zap-report.json")
        osv = load_json_safe(report_dir / "osv-report.json")
        ruff_rep = load_json_safe(report_dir / "ruff-report.json")
        semgrep_rep = load_json_safe(report_dir / "semgrep-report.json")
        
        # Quick check for blocks
        is_blocked = False
        reasons = []
        if clamav and len(clamav) > 0:
            is_blocked = True
            reasons.append("ClamAV")
        if zap and len([z for z in zap if z.get("status") == "EXPOSED"]) > 0:
            is_blocked = True
            reasons.append("Aegis DAST Probe")
        if ruff_rep and isinstance(ruff_rep, list):
            blocking_issues = [
                r for r in ruff_rep
                if get_ruff_severity(r.get("code", "UNKNOWN")) in {"MEDIUM", "HIGH"}
            ]
            if len(blocking_issues) > 0:
                is_blocked = True
                reasons.append("Ruff (SAST)")
        if semgrep_rep and isinstance(semgrep_rep, dict):
            if len([r for r in semgrep_rep.get("results", []) if r.get("extra", {}).get("severity", "").upper() in {"ERROR", "WARNING"}]) > 0:
                is_blocked = True
                reasons.append("Semgrep")
        if osv and isinstance(osv, list):
            if len([f for f in osv if (f.get("cvss") or 0.0) >= 4.0]) > 0:
                is_blocked = True
                reasons.append("OSV Dependency Audit")

        from main import calculate_exploitability_score
        score = calculate_exploitability_score(report_dir, waf_enabled)
        _mirror_latest_reports(report_dir)
        
        result_payload = {
            "clamav": clamav,
            "zap": zap,
            "osv": osv,
            "ruff": ruff_rep,
            "semgrep": semgrep_rep,
            "exploitability_score": score,
            "waf_enabled": waf_enabled,
            "has_run": True,
            "is_blocked": is_blocked,
            "blocked_by": reasons,
            "sandbox_status": "active" if sandbox_active else "simulated_fallback"
        }

        # 5. State: REPORTING -> COMPLETED
        if scan_run_id:
            update_scan_run(
                scan_run_id, state="completed", progress=100, result=result_payload
            )
        if project_id:
            project = get_project(project_id)
            send_project_notification(
                project_id,
                "blocked" if is_blocked else "completed",
                {
                    "project_name": project["name"] if project else "Project",
                    "job_id": job_id,
                    "new_findings": result_payload.get("new_findings", 0),
                    "is_blocked": is_blocked,
                    "blocked_by": reasons,
                },
            )
        publish_job_event(job_id, "result", {"result": result_payload})
        publish_job_event(job_id, "state", {"state": "completed", "progress": 100})
        publish_job_event(job_id, "log", {"text": "[OK] GATE VERDICT READY: Scan execution completed successfully.", "color": "var(--primary)"})
        
    except ScanCancelled:
        if scan_run_id:
            update_scan_run(scan_run_id, state="cancelled", progress=100)
        publish_job_event(job_id, "state", {"state": "cancelled", "progress": 100})
        publish_job_event(job_id, "log", {"text": "[SYSTEM] Scan cancelled by user.", "color": "var(--secondary)"})
        if project_id:
            project = get_project(project_id)
            send_project_notification(project_id, "cancelled", {
                "project_name": project["name"] if project else "Project",
                "job_id": job_id,
            })
    except Exception as e:
        if scan_run_id:
            update_scan_run(scan_run_id, state="failed", progress=100)
        publish_job_event(job_id, "state", {"state": "failed", "progress": 100})
        publish_job_event(job_id, "log", {"text": f"[FATAL] Scan job execution failed: {e}", "color": "var(--danger)"})
        redis_client.hset(f"job:{job_id}", "error", str(e))
        if project_id:
            project = get_project(project_id)
            send_project_notification(project_id, "failed", {
                "project_name": project["name"] if project else "Project",
                "job_id": job_id,
                "error": str(e)[:500],
            })
        raise e
    finally:
        if external_project_dir:
            shutil.rmtree(external_project_dir, ignore_errors=True)
