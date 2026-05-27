import os
import sys
import re
import uuid
import json
import shutil
import socket
import subprocess
import time
import pickle
import hashlib
import sqlite3
from pathlib import Path
import redis

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))
sys.path.append(str(Path(__file__).resolve().parent))

from database import DB_PATH, BASE_DIR, PROJECT_ROOT, DOWNLOAD_DIR, SCANS_DIR
from sandbox import (
    is_docker_available, scaffold_sandbox_context, build_sandbox_image,
    run_sandbox_container, wait_for_container, run_trivy_scan, stop_and_cleanup_sandbox,
    get_active_sandbox_container, get_sandbox_stats, get_sandbox_logs
)

redis_client = redis.Redis(host=os.environ.get("REDIS_HOST", "localhost"), port=6379, db=0)

def publish_job_event(job_id: str, event_type: str, data: dict):
    channel = f"job_channel:{job_id}"
    payload = {"type": event_type, **data}
    
    if event_type == "state":
        redis_client.hset(f"job:{job_id}", "state", data.get("state", ""))
        redis_client.hset(f"job:{job_id}", "progress", data.get("progress", 0))
    elif event_type == "result":
        redis_client.hset(f"job:{job_id}", "result", json.dumps(data.get("result", {})))
        
    if event_type == "log":
        redis_client.rpush(f"job_logs:{job_id}", json.dumps(data))
        
    redis_client.publish(channel, json.dumps(payload))

def load_waf_rules_from_db():
    conn = sqlite3.connect(DB_PATH)
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
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()

def write_semgrep_rules(path):
    rules_content = """rules:
  - id: python-sqli
    patterns:
      - pattern-either:
          - pattern: $CURSOR.execute(..., $VAR)
          - pattern: $CURSOR.execute(f"...")
          - pattern: $CURSOR.execute("..." % ...)
      - pattern-not:
          - pattern: $CURSOR.execute("...", ...)
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
    path.write_text(rules_content)

def run_yara_scan(target_path: str, job_id: str):
    findings = []
    # 1. Try to scan using the compiled yara-python library
    try:
        import yara
        yara_rules_path = PROJECT_ROOT / "rules" / "aegis_rules.yar"
        if not yara_rules_path.exists():
            yara_rules_path = Path("rules/aegis_rules.yar")
        
        if yara_rules_path.exists():
            rules = yara.compile(filepath=str(yara_rules_path))
            
            def scan_file(file_path):
                try:
                    matches = rules.match(filepath=str(file_path))
                    for m in matches:
                        finding = {
                            "rule": m.rule,
                            "filename": str(file_path),
                            "description": m.meta.get("description", "YARA rule match"),
                            "author": m.meta.get("author", "Aegis")
                        }
                        findings.append(finding)
                        publish_job_event(job_id, "log", {"text": f"[YARA] MATCH: {m.rule} in {file_path}", "color": "var(--secondary)"})
                except Exception as e:
                    publish_job_event(job_id, "log", {"text": f"[YARA Error] {file_path}: {e}", "color": "var(--danger)"})

            p = Path(target_path)
            if p.is_dir():
                for root, dirs, files in os.walk(p):
                    for file in files:
                        if file.endswith(".py"):
                            scan_file(Path(root) / file)
            else:
                scan_file(p)
            return findings
    except ImportError:
        publish_job_event(job_id, "log", {"text": "[YARA] yara-python missing. Falling back to signature scan.", "color": "var(--secondary)"})

    # 2. Fallback regex-based signature scanner
    def scan_file_fallback(file_path):
        try:
            content = file_path.read_text(errors='ignore')
            
            # Rule 1: Backdoor_Webshell
            p1 = re.search(r'eval\(\s*request\.(args|form|values)', content)
            p2 = re.search(r'exec\(\s*request\.(args|form|values)', content)
            p3 = re.search(r'subprocess\.Popen\(\s*request\.args', content)
            p4 = re.search(r'subprocess\.check_output\(\s*request\.args', content)
            if p1 or p2 or p3 or p4:
                findings.append({
                    "rule": "Backdoor_Webshell",
                    "filename": str(file_path),
                    "description": "Detects Python webshell or remote command execution patterns",
                    "author": "Aegis Secure Console (Fallback)"
                })
                publish_job_event(job_id, "log", {"text": f"[YARA Fallback] MATCH: Backdoor_Webshell in {file_path}", "color": "var(--secondary)"})
                
            # Rule 2: Obfuscated_Payload
            has_b64 = "base64.b64decode" in content
            has_exec = "exec(" in content
            has_eval = "eval(" in content
            if has_b64 and (has_exec or has_eval):
                findings.append({
                    "rule": "Obfuscated_Payload",
                    "filename": str(file_path),
                    "description": "Detects base64 obfuscation combined with execution",
                    "author": "Aegis Secure Console (Fallback)"
                })
                publish_job_event(job_id, "log", {"text": f"[YARA Fallback] MATCH: Obfuscated_Payload in {file_path}", "color": "var(--secondary)"})
                
            # Rule 3: Suspicious_Shell_Spawn
            has_sh = ("/bin/sh" in content) or ("/bin/bash" in content)
            has_pty = "pty.spawn" in content
            has_socket = "socket.socket" in content
            has_sub = ("subprocess.Popen" in content) or ("subprocess.call" in content)
            if (has_sh and has_pty) or (has_socket and has_sub and has_sh):
                findings.append({
                    "rule": "Suspicious_Shell_Spawn",
                    "filename": str(file_path),
                    "description": "Detects shell spawning commands, likely for reverse shells",
                    "author": "Aegis Secure Console (Fallback)"
                })
                publish_job_event(job_id, "log", {"text": f"[YARA Fallback] MATCH: Suspicious_Shell_Spawn in {file_path}", "color": "var(--secondary)"})
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[Fallback Scan Error] {file_path}: {e}", "color": "var(--danger)"})

    p = Path(target_path)
    if p.is_dir():
        for root, dirs, files in os.walk(p):
            for file in files:
                if file.endswith(".py"):
                    scan_file_fallback(Path(root) / file)
    else:
        scan_file_fallback(p)
        
    return findings

def run_clamav_scan(target_path: str, job_id: str):
    findings = []
    import shutil
    clamscan_bin = shutil.which("clamscan")
    if clamscan_bin:
        try:
            publish_job_event(job_id, "log", {"text": "[ClamAV] Starting ClamAV scanning CLI...", "color": "var(--text-muted)"})
            result = subprocess.run([clamscan_bin, "-r", "--infected", target_path], capture_output=True, text=True, check=False)
            for line in result.stdout.splitlines():
                if "FOUND" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        filename = parts[0].strip()
                        virus_part = parts[1].replace("FOUND", "").strip()
                        findings.append({
                            "filename": filename,
                            "virus": virus_part,
                            "description": f"ClamAV detected malware signature: {virus_part}"
                        })
                        publish_job_event(job_id, "log", {"text": f"[ClamAV] MATCH: {virus_part} in {filename}", "color": "var(--secondary)"})
            return findings
        except Exception as e:
            publish_job_event(job_id, "log", {"text": f"[ClamAV Error] {e}", "color": "var(--danger)"})

    # Fallback pure-Python scan
    eicar_sig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    def scan_file_clamav(file_path):
        try:
            content = file_path.read_text(errors='ignore')
            if eicar_sig in content:
                findings.append({
                    "filename": str(file_path),
                    "virus": "EICAR-Test-Signature",
                    "description": "Matched EICAR standard antivirus test signature"
                })
                publish_job_event(job_id, "log", {"text": f"[ClamAV Fallback] MATCH: EICAR-Test-Signature in {file_path}", "color": "var(--secondary)"})
            # Check for base64 backdoors
            if re.search(r'(eval|exec)\(\s*base64\.b64decode', content):
                findings.append({
                    "filename": str(file_path),
                    "virus": "Python.Backdoor.Base64Decoder",
                    "description": "Detected base64-encoded Python execution pattern, indicating potential backdoor/webshell"
                })
                publish_job_event(job_id, "log", {"text": f"[ClamAV Fallback] MATCH: Python.Backdoor.Base64Decoder in {file_path}", "color": "var(--secondary)"})
        except Exception:
            pass

    p = Path(target_path)
    if p.is_dir():
        for root, dirs, files in os.walk(p):
            if any(k in root for k in ["venv", "scanner-venv", ".git", ".pytest_cache", ".antigravitycli"]):
                continue
            for file in files:
                if file.endswith(".py") or file.endswith(".txt"):
                    scan_file_clamav(Path(root) / file)
    else:
        scan_file_clamav(p)

    return findings

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

def execute_subprocess_log(cmd, cwd, job_id, tool_name):
    publish_job_event(job_id, "log", {"text": f"[{tool_name}] Executing: {' '.join(cmd)}", "color": "var(--text-muted)"})
    try:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in p.stdout:
            publish_job_event(job_id, "log", {"text": f"[{tool_name}] {line.strip()}", "color": "var(--text-main)"})
        p.wait()
        return p.returncode
    except Exception as e:
        publish_job_event(job_id, "log", {"text": f"[{tool_name} Error] Failed to run command: {e}", "color": "var(--danger)"})
        return -1

def async_scan_task(job_id: str, target: str, custom_file_path: str = None, waf_enabled: bool = False):
    try:
        python_bin = sys.executable
        is_custom_scan = custom_file_path is not None
        target_path = custom_file_path if is_custom_scan else None
        
        # 1. State: QUEUED -> RUNNING
        publish_job_event(job_id, "state", {"state": "running", "progress": 10})
        publish_job_event(job_id, "log", {"text": f"[SYSTEM] Job claimed by worker. Job ID: {job_id}", "color": "var(--primary)"})
        
        if is_custom_scan:
            target_path = custom_file_path
            # Empty placeholders for custom scans
            with open(SCANS_DIR / "safety-report.json", "w") as f:
                json.dump([], f)
            with open(SCANS_DIR / "trivy-report.json", "w") as f:
                json.dump({"Results": []}, f)
        else:
            if target == "secure":
                target_path = str(BASE_DIR / "secure_main.py")
            else:
                target_path = str(BASE_DIR / "main.py")
                
            # Run Safety SCA
            publish_job_event(job_id, "log", {"text": "[SCA] Auditing dependencies via Safety...", "color": "var(--text-muted)"})
            safety_cmd = [python_bin, "-m", "safety", "check", "-r", "requirements.txt", "--save-json", str(SCANS_DIR / "safety-report.json")]
            subprocess.run(safety_cmd, cwd=PROJECT_ROOT, check=False)
            publish_job_event(job_id, "log", {"text": "[SCA] Safety scan complete.", "color": "var(--primary)"})
            
            # Ensure trivy-report.json exists
            trivy_path = SCANS_DIR / "trivy-report.json"
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
        sandbox_temp_dir = SCANS_DIR / "sandbox" / sandbox_uuid
        host_port = None

        def find_free_port() -> int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', 0))
                return s.getsockname()[1]

        if is_docker_available() and has_python:
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

        sandbox_status_file = SCANS_DIR / "sandbox-status.json"
        try:
            with open(sandbox_status_file, "w") as sf:
                json.dump({"status": "active" if sandbox_active else "simulated_fallback"}, sf)
        except Exception:
            pass

        # 2. State: RUNNING -> ANALYZING
        publish_job_event(job_id, "state", {"state": "analyzing", "progress": 30})
        
        # SAST: Bandit
        bandit_report_path = SCANS_DIR / "bandit-report.json"
        if has_python:
            bandit_cmd = [python_bin, "-m", "bandit"]
            if is_dir:
                bandit_cmd.append("-r")
            bandit_cmd.extend([target_path, "-f", "json", "-o", str(bandit_report_path)])
            execute_subprocess_log(bandit_cmd, PROJECT_ROOT, job_id, "SAST:Bandit")
        else:
            with open(bandit_report_path, "w") as f:
                json.dump({"results": []}, f)
            publish_job_event(job_id, "log", {"text": "[SAST:Bandit] Skipped (No Python scripts found)", "color": "var(--text-muted)"})

        # SAST: Semgrep
        semgrep_report_path = SCANS_DIR / "semgrep-report.json"
        if has_python:
            try:
                semgrep_rules_path = PROJECT_ROOT / "rules" / "semgrep_rules.yaml"
                if not semgrep_rules_path.exists():
                    semgrep_rules_path.parent.mkdir(exist_ok=True, parents=True)
                    write_semgrep_rules(semgrep_rules_path)
                
                semgrep_bin = Path(python_bin).parent / "semgrep"
                if not semgrep_bin.exists():
                    semgrep_cmd = ["semgrep", "scan", "--config", str(semgrep_rules_path), "--json", "-o", str(semgrep_report_path), target_path]
                else:
                    semgrep_cmd = [str(semgrep_bin), "scan", "--config", str(semgrep_rules_path), "--json", "-o", str(semgrep_report_path), target_path]
                execute_subprocess_log(semgrep_cmd, PROJECT_ROOT, job_id, "SAST:Semgrep")
            except Exception as e:
                with open(semgrep_report_path, "w") as f:
                    json.dump({"results": []}, f)
        else:
            with open(semgrep_report_path, "w") as f:
                json.dump({"results": []}, f)
            publish_job_event(job_id, "log", {"text": "[SAST:Semgrep] Skipped (No Python scripts found)", "color": "var(--text-muted)"})

        # Secrets Scanner
        secrets_report_path = SCANS_DIR / "secrets-report.json"
        try:
            secrets_cmd = [
                python_bin, "-m", "detect_secrets", "scan", "--all-files",
                "--exclude-files", "venv/|scanner-venv/|tests/|scans/|\\.pytest_cache/|\\.git/|\\.antigravitycli/",
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
        yara_report_path = SCANS_DIR / "yara-report.json"
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
        clamav_report_path = SCANS_DIR / "clamav-report.json"
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

        # ZAP DAST Scanner
        zap_report_path = SCANS_DIR / "zap-report.json"
        try:
            publish_job_event(job_id, "log", {"text": "[DAST] Running active crawler against endpoints...", "color": "var(--text-muted)"})
            if sandbox_active:
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
                run_trivy_scan(sandbox_image, SCANS_DIR / "trivy-report.json")
                publish_job_event(job_id, "log", {"text": "[Trivy] Image layer audit complete.", "color": "var(--primary)"})
            except Exception as e:
                publish_job_event(job_id, "log", {"text": f"[Trivy Error] {e}", "color": "var(--danger)"})

        # 3. State: ANALYZING -> CORRELATING
        publish_job_event(job_id, "state", {"state": "correlating", "progress": 70})
        publish_job_event(job_id, "log", {"text": "[SYSTEM] Evaluating scanner outputs against security gate thresholds...", "color": "var(--text-muted)"})
        
        # Run policy engine
        engine_path = PROJECT_ROOT / "policy_engine.py"
        engine_cmd = [python_bin, str(engine_path)]
        execute_subprocess_log(engine_cmd, PROJECT_ROOT, job_id, "PolicyEngine")

        # 4. State: CORRELATING -> REPORTING
        publish_job_event(job_id, "state", {"state": "reporting", "progress": 90})
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
            
        clamav = load_json_safe(SCANS_DIR / "clamav-report.json")
        zap = load_json_safe(SCANS_DIR / "zap-report.json")
        osv = load_json_safe(SCANS_DIR / "osv-report.json")
        bandit_rep = load_json_safe(SCANS_DIR / "bandit-report.json")
        semgrep_rep = load_json_safe(SCANS_DIR / "semgrep-report.json")
        
        # Quick check for blocks
        is_blocked = False
        reasons = []
        if clamav and len(clamav) > 0:
            is_blocked = True
            reasons.append("ClamAV")
        if zap and len([z for z in zap if z.get("status") == "EXPOSED"]) > 0:
            is_blocked = True
            reasons.append("ZAP DAST")
        if bandit_rep and isinstance(bandit_rep, dict):
            if len([r for r in bandit_rep.get("results", []) if r.get("issue_severity", "").upper() in {"MEDIUM", "HIGH"}]) > 0:
                is_blocked = True
                reasons.append("Bandit")
        if semgrep_rep and isinstance(semgrep_rep, dict):
            if len([r for r in semgrep_rep.get("results", []) if r.get("extra", {}).get("severity", "").upper() in {"ERROR", "WARNING"}]) > 0:
                is_blocked = True
                reasons.append("Semgrep")
        if osv and isinstance(osv, list):
            if len([f for f in osv if (f.get("cvss") or 0.0) >= 4.0]) > 0:
                is_blocked = True
                reasons.append("OSV Dependency Audit")

        from main import calculate_exploitability_score
        score = calculate_exploitability_score(SCANS_DIR, waf_enabled)
        
        result_payload = {
            "clamav": clamav,
            "zap": zap,
            "osv": osv,
            "exploitability_score": score,
            "waf_enabled": waf_enabled,
            "has_run": True,
            "is_blocked": is_blocked,
            "blocked_by": reasons,
            "sandbox_status": "active" if sandbox_active else "simulated_fallback"
        }

        # 5. State: REPORTING -> COMPLETED
        publish_job_event(job_id, "result", {"result": result_payload})
        publish_job_event(job_id, "state", {"state": "completed", "progress": 100})
        publish_job_event(job_id, "log", {"text": "[OK] GATE VERDICT READY: Scan execution completed successfully.", "color": "var(--primary)"})
        
    except Exception as e:
        publish_job_event(job_id, "state", {"state": "failed", "progress": 100})
        publish_job_event(job_id, "log", {"text": f"[FATAL] Scan job execution failed: {e}", "color": "var(--danger)"})
        redis_client.hset(f"job:{job_id}", "error", str(e))
        raise e
