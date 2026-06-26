import base64
import hashlib
import os
import pickle
import re
import sqlite3
import subprocess
import sys
import time
import random
import json
import asyncio
import uuid
from pathlib import Path

# Add the current directory and project root to sys.path to allow imports
sys.path.append(str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent))

# Ensure the virtual environment's bin/Scripts directory is in PATH so that packages
# invoking subprocesses (like semgrep) can find their corresponding executables.
sys_exec_dir = os.path.dirname(sys.executable)
if sys_exec_dir and sys_exec_dir not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = sys_exec_dir + os.pathsep + os.environ.get("PATH", "")

from fastapi import FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from werkzeug.utils import secure_filename
import redis

from database import DB_PATH, initialize_database, BASE_DIR, PROJECT_ROOT, DOWNLOAD_DIR, SCANS_DIR, redis_client, REDIS_AVAILABLE
from policy_engine import get_ruff_severity
from sandbox import (
    is_docker_available, scaffold_sandbox_context, build_sandbox_image,
    run_sandbox_container, wait_for_container, run_trivy_scan, stop_and_cleanup_sandbox,
    get_active_sandbox_container, get_sandbox_stats, get_sandbox_logs
)

app = FastAPI(title="Aegis DevSecOps Console")

# Enable CORS for convenience
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Global state for the WAF toggle (demo only)
WAF_ENABLED = os.environ.get("WAF_ENABLED", "false").lower() == "true"

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
        return [
            {"pattern": "' OR '", "description": "SQL Injection (OR operator bypass)", "enabled": True},
            {"pattern": "1=1", "description": "SQL Injection (tautology bypass)", "enabled": True},
            {"pattern": "--", "description": "SQL comment character block", "enabled": True},
            {"pattern": "cat /etc/passwd", "description": "LFI/Command execution pattern 1", "enabled": True},
            {"pattern": "\\.\\./", "description": "Directory Traversal pattern (../)", "enabled": True},
            {"pattern": "pickle\\.loads", "description": "Python deserialization hijack detector", "enabled": True},
            {"pattern": "eval\\(", "description": "Python dynamic expression injection detector", "enabled": True},
            {"pattern": "__import__|system\\(|subprocess", "description": "Python code execution attempt", "enabled": True},
            {"pattern": "<\\s*script", "description": "XSS (Dangerous script tags)", "enabled": True},
            {"pattern": "on\\w+\\s*=", "description": "XSS (HTML event handler hijacking)", "enabled": True},
            {"pattern": "javascript\\s*:", "description": "XSS (Javascript URI prefix)", "enabled": True},
            {"pattern": "169\\.254\\.169\\.254", "description": "SSRF (Cloud metadata server IP)", "enabled": True},
            {"pattern": "localhost|127\\.0\\.0\\.1", "description": "SSRF (Localhost lookup blocker)", "enabled": True}
        ]
    finally:
        conn.close()

def save_waf_rules_to_db(rules):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM waf_rules")
        for r in rules:
            cursor.execute(
                "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
                (r["pattern"], r["description"], 1 if r["enabled"] else 0)
            )
        conn.commit()
    finally:
        conn.close()

def extract_json_values(data):
    if isinstance(data, dict):
        parts = []
        for k, v in data.items():
            parts.append(str(k))
            parts.append(extract_json_values(v))
        return " ".join(parts)
    elif isinstance(data, list):
        return " ".join(extract_json_values(item) for item in data)
    else:
        return str(data)

def calculate_exploitability_score(scans_dir: Path, waf_enabled: bool) -> float:
    def read_json_safe(p):
        if p.exists():
            try:
                return json.loads(p.read_text())
            except Exception:
                pass
        return None

    ruff = read_json_safe(scans_dir / "ruff-report.json")
    semgrep = read_json_safe(scans_dir / "semgrep-report.json")
    safety = read_json_safe(scans_dir / "safety-report.json")
    trivy = read_json_safe(scans_dir / "trivy-report.json")
    secrets = read_json_safe(scans_dir / "secrets-report.json")
    yara = read_json_safe(scans_dir / "yara-report.json")
    clamav = read_json_safe(scans_dir / "clamav-report.json")
    zap = read_json_safe(scans_dir / "zap-report.json")
    osv = read_json_safe(scans_dir / "osv-report.json")

    findings = []
    dast_exposed_multiplier = 1.0

    if ruff and isinstance(ruff, list):
        for r in ruff:
            sev = get_ruff_severity(r.get("code", "UNKNOWN"))
            cvss = 8.5 if sev == "HIGH" else (5.5 if sev == "MEDIUM" else 2.0)
            findings.append({"type": "sast", "cvss": cvss})

    if semgrep and isinstance(semgrep, dict):
        for r in semgrep.get("results", []):
            sev = r.get("extra", {}).get("severity", "ERROR").upper()
            cvss = 8.5 if sev == "ERROR" else (5.5 if sev == "WARNING" else 2.0)
            findings.append({"type": "sast", "cvss": cvss})

    if not osv and safety:
        vulns = []
        if isinstance(safety, dict):
            vulns = safety.get("vulnerabilities", []) or safety.get("results", [])
        elif isinstance(safety, list):
            vulns = safety
        for v in vulns:
            findings.append({"type": "sca", "cvss": 6.5})

    if osv and isinstance(osv, list):
        for vuln in osv:
            cvss = vuln.get("cvss") or 6.5
            findings.append({"type": "sca", "cvss": cvss})

    if trivy and isinstance(trivy, dict):
        for res in trivy.get("Results", []):
            for v in res.get("Vulnerabilities", []) or []:
                sev = v.get("Severity", "LOW").upper()
                cvss = 9.8 if sev == "CRITICAL" else (8.0 if sev == "HIGH" else (5.0 if sev == "MEDIUM" else 2.0))
                findings.append({"type": "container", "cvss": cvss})

    if secrets and isinstance(secrets, dict):
        for filename, file_secrets in secrets.get("results", {}).items():
            for secret in file_secrets:
                findings.append({"type": "secrets", "cvss": 8.5})

    if yara and isinstance(yara, list):
        for _ in yara:
            findings.append({"type": "malware", "cvss": 9.0})

    if clamav and isinstance(clamav, list):
        for _ in clamav:
            findings.append({"type": "malware", "cvss": 9.0})

    if zap and isinstance(zap, list):
        exposed_count = len([z for z in zap if z.get("status") == "EXPOSED"])
        if exposed_count > 0:
            dast_exposed_multiplier = 1.5
        for z in zap:
            if z.get("status") == "EXPOSED":
                findings.append({"type": "dast", "cvss": 8.5})

    if not findings:
        return 0.0

    weighted_sum = 0.0
    weights = {
        "sast": 1.0,
        "sca": 0.8,
        "container": 0.9,
        "secrets": 1.2,
        "malware": 1.1,
        "dast": 1.0
    }
    
    for f in findings:
        w = weights.get(f["type"], 1.0)
        weighted_sum += f["cvss"] * w

    base_score = min(100.0, weighted_sum * 5.0)
    score = base_score * dast_exposed_multiplier
    
    if waf_enabled:
        score *= 0.5
        
    return round(min(100.0, score), 1)

def generate_fallback_tree():
    import re
    req_path = PROJECT_ROOT / "requirements.txt"
    if not req_path.exists():
        req_path = Path("requirements.txt")
    
    tree = []
    if req_path.exists():
        try:
            content = req_path.read_text()
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = re.match(r'^([a-zA-Z0-9_\-]+)\s*(==|>=)\s*([a-zA-Z0-9_\-\.]+)', line)
                if match:
                    pkg_name = match.group(1)
                    pkg_ver = match.group(3)
                    tree.append({
                        "key": pkg_name.lower(),
                        "package_name": pkg_name,
                        "installed_version": pkg_ver,
                        "required_version": f"=={pkg_ver}",
                        "dependencies": []
                    })
        except Exception:
            pass
    return tree

# Use environment variables for secrets.
app.state.secret_key = os.environ.get("SECRET_KEY", "default-dev-secret-key")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "dev-password")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "DEV-AWS-ID")

# Initialize directories safely
DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
SCANS_DIR.mkdir(exist_ok=True, parents=True)

sample_file = DOWNLOAD_DIR / "sample.txt"
if not sample_file.exists():
    sample_file.write_text("This is a safe sample file.\n")

if not DB_PATH.exists():
    initialize_database()

# Custom ASGI middleware for WAF checks (replaces BaseHTTPMiddleware to prevent TestClient hangs)
import urllib.parse

class WafASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        global WAF_ENABLED
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in ["/toggle-waf", "/get-waf-rules", "/save-waf-rules", "/run-scan", "/export-dossier"]:
            await self.app(scope, receive, send)
            return

        if not WAF_ENABLED:
            await self.app(scope, receive, send)
            return

        # Read query params
        query_string = scope.get("query_string", b"").decode('utf-8', errors='ignore')
        query_string_decoded = urllib.parse.unquote_plus(query_string)

        # Cache request body
        body_chunks = []
        more_body = True
        while more_body:
            message = await receive()
            body_chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)

        body = b"".join(body_chunks)

        # Re-create receive channel
        sent_body = False
        async def cached_receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False
                }
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False
            }

        payload_parts = [query_string_decoded]
        if body:
            try:
                body_str = body.decode('utf-8', errors='ignore')
                payload_parts.append(body_str)
                payload_parts.append(urllib.parse.unquote_plus(body_str))
            except Exception:
                payload_parts.append(str(body))
        
        payload = " ".join(payload_parts)

        # Run WAF rules check
        blocked = False
        block_reason = ""
        rules = load_waf_rules_from_db()
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            try:
                if re.search(pattern, payload, re.IGNORECASE):
                    blocked = True
                    block_reason = f"Detected malicious pattern: {rule.get('description', pattern)}"
                    break
            except re.error:
                if pattern in payload:
                    blocked = True
                    block_reason = f"Detected malicious pattern (literal): {rule.get('description', pattern)}"
                    break

        if blocked:
            # Send 403 Forbidden ASGI response directly
            response_content = json.dumps({
                "error": "Blocked by Aegis WAF",
                "reason": block_reason,
                "status": "security_violation"
            }).encode('utf-8')
            
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(response_content)).encode('utf-8'))
                ]
            })
            await send({
                "type": "http.response.body",
                "body": response_content,
                "more_body": False
            })
            return

        await self.app(scope, cached_receive, send)

app.add_middleware(WafASGIMiddleware)

# REST Router Endpoints
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/report", response_class=HTMLResponse)
def get_report():
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        return HTMLResponse("<h1>Report not found</h1><p>Please run the security scans first.</p>", status_code=404)
    return HTMLResponse(report_path.read_text())

@app.get("/download-sbom")
def download_sbom():
    sbom_path = SCANS_DIR / "sbom.json"
    if not sbom_path.exists():
        from policy_engine import generate_cyclonedx_sbom
        try:
            req_path = PROJECT_ROOT / "requirements.txt"
            if not req_path.exists():
                req_path = Path("requirements.txt")
            generate_cyclonedx_sbom(req_path, sbom_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"SBOM generation failed: {e}")
            
    return FileResponse(
        str(sbom_path),
        media_type="application/json",
        filename="cyclonedx-sbom.json"
    )

@app.post("/toggle-waf")
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    return {"status": "success", "waf_enabled": WAF_ENABLED}

@app.get("/get-waf-rules")
def get_waf_rules():
    global WAF_ENABLED
    rules = load_waf_rules_from_db()
    return {"status": "success", "rules": rules, "waf_enabled": WAF_ENABLED}

@app.post("/save-waf-rules")
async def save_waf_rules(request: Request):
    try:
        data = await request.json()
        rules = data.get("rules", [])
        new_rules = []
        for r in rules:
            if "pattern" in r:
                new_rules.append({
                    "pattern": str(r["pattern"]),
                    "description": str(r.get("description", "")),
                    "enabled": bool(r.get("enabled", True))
                })
        save_waf_rules_to_db(new_rules)
        return {"status": "success", "message": "WAF rules updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/get-scan-results")
def get_scan_results():
    global WAF_ENABLED
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
    ruff = load_json_safe(SCANS_DIR / "ruff-report.json")
    semgrep = load_json_safe(SCANS_DIR / "semgrep-report.json")
    safety = load_json_safe(SCANS_DIR / "safety-report.json")
    trivy = load_json_safe(SCANS_DIR / "trivy-report.json")
    secrets = load_json_safe(SCANS_DIR / "secrets-report.json")
    yara = load_json_safe(SCANS_DIR / "yara-report.json")
    
    score = calculate_exploitability_score(SCANS_DIR, WAF_ENABLED)
    
    is_blocked = False
    reasons = []
    
    if clamav and len(clamav) > 0:
        is_blocked = True
        reasons.append("ClamAV")
    if zap and len([z for z in zap if z.get("status") == "EXPOSED"]) > 0:
        is_blocked = True
        reasons.append("ZAP DAST")
        
    if ruff and isinstance(ruff, list):
        blocking_ruff = len([r for r in ruff if get_ruff_severity(r.get("code", "UNKNOWN")) in {"MEDIUM", "HIGH"}])
        if blocking_ruff > 0:
            is_blocked = True
            reasons.append("Ruff (SAST)")
            
    if semgrep and isinstance(semgrep, dict):
        blocking_semgrep = len([r for r in semgrep.get("results", []) if r.get("extra", {}).get("severity", "").upper() in {"ERROR", "WARNING"}])
        if blocking_semgrep > 0:
            is_blocked = True
            reasons.append("Semgrep")
            
    if osv and isinstance(osv, list):
        blocking_osv = len([f for f in osv if (f.get("cvss") or 0.0) >= 4.0])
        if blocking_osv > 0:
            is_blocked = True
            reasons.append("OSV Dependency Audit")
            
    has_run = any(report is not None for report in [ruff, semgrep, osv, safety, trivy, secrets, yara, clamav, zap])

    latest_report = SCANS_DIR / "report.html"
    latest_scan_time = None
    if latest_report.exists():
        latest_scan_time = latest_report.stat().st_mtime

    sandbox_status_file = SCANS_DIR / "sandbox-status.json"
    sandbox_status = "simulated_fallback"
    if sandbox_status_file.exists():
        try:
            sandbox_status = json.loads(sandbox_status_file.read_text()).get("status", "simulated_fallback")
        except Exception:
            pass

    return {
        "clamav": clamav,
        "zap": zap,
        "osv": osv,
        "ruff": ruff,
        "semgrep": semgrep,
        "safety": safety,
        "trivy": trivy,
        "secrets": secrets,
        "yara": yara,
        "exploitability_score": score,
        "waf_enabled": WAF_ENABLED,
        "has_run": has_run,
        "is_blocked": is_blocked,
        "blocked_by": reasons,
        "sandbox_status": sandbox_status,
        "latest_scan_time": latest_scan_time,
        "report_url": "/report" if latest_report.exists() else None,
        "markdown_url": "/export-dossier" if latest_report.exists() else None,
        "sbom_url": "/download-sbom" if (SCANS_DIR / "sbom.json").exists() else None
    }

@app.get("/get-dependency-graph")
def get_dependency_graph():
    vulnerable_packages = set()
    safety_path = SCANS_DIR / "safety-report.json"
    if safety_path.exists():
        try:
            report = json.loads(safety_path.read_text())
            if isinstance(report, dict) and "vulnerabilities" in report:
                for v in report["vulnerabilities"]:
                    pkg = v.get("package_name") or v.get("package")
                    if pkg:
                        vulnerable_packages.add(pkg.lower())
            elif isinstance(report, list):
                for v in report:
                    pkg = v.get("package_name") or v.get("package")
                    if pkg:
                        vulnerable_packages.add(pkg.lower())
            elif isinstance(report, dict) and "affected_packages" in report:
                for pkg in report["affected_packages"].keys():
                    vulnerable_packages.add(pkg.lower())
        except Exception:
            pass

    osv_vulnerabilities = {}
    osv_path = SCANS_DIR / "osv-report.json"
    if osv_path.exists():
        try:
            osv_findings = json.loads(osv_path.read_text())
            if isinstance(osv_findings, list):
                for f in osv_findings:
                    pkg = f.get("package")
                    if pkg:
                        pkg_lower = pkg.lower()
                        if pkg_lower not in osv_vulnerabilities:
                            osv_vulnerabilities[pkg_lower] = []
                        osv_vulnerabilities[pkg_lower].append({
                            "id": f.get("id"),
                            "cvss": f.get("cvss"),
                            "summary": f.get("summary")
                        })
        except Exception:
            pass

    raw_tree = []
    try:
        python_bin = sys.executable
        pipdeptree_bin = Path(python_bin).parent / "pipdeptree"
        if not pipdeptree_bin.exists():
            pipdeptree_cmd = [python_bin, "-m", "pipdeptree", "--json-tree"]
        else:
            pipdeptree_cmd = [str(pipdeptree_bin), "--json-tree"]
        
        result = subprocess.run(pipdeptree_cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            raw_tree = json.loads(result.stdout)
        else:
            raw_tree = generate_fallback_tree()
    except Exception:
        raw_tree = generate_fallback_tree()

    nodes = {}
    links = []
    
    nodes["aegis"] = {
        "id": "aegis",
        "name": "Aegis (Root)",
        "installed_version": "1.0.0",
        "required_version": "N/A",
        "vulnerable": False,
        "isRoot": True,
        "vulnerabilities": []
    }
    
    def walk(dep_list, parent_id):
        for dep in dep_list:
            pkg_name = dep.get("package_name") or dep.get("key")
            pkg_key = (dep.get("key") or pkg_name.lower()).replace("-", "_")
            installed = dep.get("installed_version", "unknown")
            required = dep.get("required_version", "unknown")
            
            link_key = (parent_id, pkg_key)
            
            pkg_lower = pkg_key.lower().replace("_", "-")
            is_vuln = (pkg_lower in vulnerable_packages or 
                       pkg_key.lower() in vulnerable_packages or 
                       pkg_lower in osv_vulnerabilities or 
                       pkg_key.lower() in osv_vulnerabilities)
            
            vuln_details = osv_vulnerabilities.get(pkg_lower) or osv_vulnerabilities.get(pkg_key.lower()) or []
            
            if pkg_key not in nodes:
                nodes[pkg_key] = {
                    "id": pkg_key,
                    "name": pkg_name,
                    "installed_version": installed,
                    "required_version": required,
                    "vulnerable": is_vuln,
                    "vulnerabilities": vuln_details
                }
            
            if link_key not in [(l["source"], l["target"]) for l in links]:
                links.append({
                    "source": parent_id,
                    "target": pkg_key,
                    "required_version": required
                })
            
            if "dependencies" in dep and dep["dependencies"]:
                walk(dep["dependencies"], pkg_key)

    walk(raw_tree, "aegis")
    
    return {
        "nodes": list(nodes.values()),
        "links": links
    }

@app.post("/run-scan")
async def run_scan(request: Request):
    if os.environ.get("VERCEL"):
        raise HTTPException(status_code=400, detail="Security scans are not supported in the Vercel serverless environment.")

    content_type = request.headers.get("content-type", "")
    uploaded_file = None
    uploaded_filename = None
    target_name = "vulnerable"

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file:
            uploaded_filename = uploaded_file.filename
    else:
        try:
            body = await request.json()
            target_name = body.get("target", "vulnerable")
        except Exception:
            try:
                form = await request.form()
                target_name = form.get("target", "vulnerable")
            except Exception:
                pass

    custom_file_path = None
    if uploaded_file and uploaded_filename:
        if not uploaded_filename.lower().endswith('.py'):
            raise HTTPException(status_code=400, detail="Invalid file type. Only Python (.py) files are allowed.")
        uuid_str = uuid.uuid4().hex
        temp_dir = SCANS_DIR / "uploads" / uuid_str
        temp_dir.mkdir(exist_ok=True, parents=True)
        temp_filepath = temp_dir / secure_filename(uploaded_filename)
        # Read uploaded bytes and write to disk
        contents = await uploaded_file.read()
        temp_filepath.write_bytes(contents)
        custom_file_path = str(temp_filepath)

    job_id = uuid.uuid4().hex
    
    # Write initial job status in Redis hash
    redis_client.hset(f"job:{job_id}", "state", "queued")
    redis_client.hset(f"job:{job_id}", "progress", 0)

    # Import worker task logic
    from worker import async_scan_task

    if REDIS_AVAILABLE:
        from rq import Queue
        from redis import Redis

        r_conn = Redis(host=os.environ.get("REDIS_HOST", "localhost"), port=6379, db=0)
        q = Queue(connection=r_conn)
        q.enqueue(async_scan_task, job_id, target_name, custom_file_path, WAF_ENABLED)
    else:
        import threading
        # Run scan task in a background thread in-process
        thread = threading.Thread(
            target=async_scan_task,
            args=(job_id, target_name, custom_file_path, WAF_ENABLED)
        )
        thread.daemon = True
        thread.start()

    return {
        "status": "success",
        "job_id": job_id,
        "state": "queued"
    }

@app.websocket("/ws/scan/{job_id}")
async def websocket_scan(websocket: WebSocket, job_id: str):
    await websocket.accept()
    
    r_conn = redis_client
    pubsub = r_conn.pubsub()
    pubsub.subscribe(f"job_channel:{job_id}")
    
    # 1. Catch up on logs
    log_key = f"job_logs:{job_id}"
    old_logs = r_conn.lrange(log_key, 0, -1)
    for log_bytes in old_logs:
        try:
            log_data = json.loads(log_bytes.decode('utf-8'))
            await websocket.send_json({"type": "log", **log_data})
        except Exception:
            pass
            
    # 2. Get latest state
    job_key = f"job:{job_id}"
    state = r_conn.hget(job_key, "state")
    progress = r_conn.hget(job_key, "progress")
    if state:
        await websocket.send_json({
            "type": "state",
            "state": state.decode('utf-8'),
            "progress": int(progress) if progress else 0
        })
        
    # 3. Stream updates
    metrics_task = asyncio.create_task(stream_telemetry_metrics_ws(websocket))
    
    try:
        while True:
            # Non-blocking poll for pubsub messages
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if message:
                data = json.loads(message['data'].decode('utf-8'))
                await websocket.send_json(data)
                if data.get("type") == "state" and data.get("state") in ("completed", "failed"):
                    break
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        metrics_task.cancel()
        pubsub.unsubscribe(f"job_channel:{job_id}")
        pubsub.close()

async def stream_telemetry_metrics_ws(websocket: WebSocket):
    sent_logs = set()
    import random
    
    while True:
        try:
            container_name = get_active_sandbox_container()
            if container_name:
                stats = get_sandbox_stats(container_name)
                cpu = stats.get("cpu", 0.0)
                memory = stats.get("memory", 0.0)
                
                cpu = max(0.0, min(100.0, cpu + random.uniform(-0.5, 0.5)))
                memory = max(0.0, min(100.0, memory + random.uniform(-0.2, 0.2)))
                latency = random.uniform(2.0, 5.0)
                
                logs = get_sandbox_logs(container_name, tail=5)
                log_entries = []
                for line in logs:
                    if line not in sent_logs:
                        sent_logs.add(line)
                        if "GET " in line or "POST " in line:
                            match = re.search(r'"(GET|POST|PUT|DELETE)\s+([^\s?]+)(\?[^\s"]*)?\s+HTTP', line)
                            if match:
                                method = match.group(1)
                                route = match.group(2)
                                params = match.group(3) or ""
                                ip_match = re.match(r'^([0-9.]+)', line)
                                src_ip = ip_match.group(1) if ip_match else "172.17.0.1"
                                status_match = re.search(r'HTTP/[0-9.]+"\s+(\d+)', line)
                                status = status_match.group(1) if status_match else "200"
                                
                                log_entries.append({
                                    "text": f"[PACKET] INBOUND TCP: Src={src_ip} Dst=127.0.0.1:5001 | {method} {route}{params} [Status={status}]",
                                    "color": "var(--primary)" if status != "403" else "var(--secondary)"
                                })
                            else:
                                log_entries.append({
                                    "text": f"[INFO] container: {line}",
                                    "color": "var(--text-muted)"
                                })
                        else:
                            log_entries.append({
                                "text": f"[INFO] container: {line}",
                                "color": "var(--text-muted)"
                            })
                

                await websocket.send_json({
                    "type": "telemetry",
                    "cpu": round(cpu, 1),
                    "memory": round(memory, 1),
                    "latency": round(latency, 1),
                    "logs": log_entries
                })
            else:
                cpu = max(5.0, min(95.0, 12.5 + random.uniform(-2.0, 2.0)))
                memory = max(5.0, min(95.0, 34.2 + random.uniform(-0.5, 0.5)))
                latency = max(1.0, min(5000.0, 15.0 + random.uniform(-1.0, 1.0)))
                
                log_entries = []
                if random.random() < 0.2:
                    syslog_templates = [
                        { "type": "INFO", "msg": "kernel: CPU temperature nominal (39C)", "color": "var(--text-muted)" },
                        { "type": "OK", "msg": "cron: PID 4519 - ran job: clean_tmp_downloads", "color": "var(--text-muted)" },
                        { "type": "INFO", "msg": "net_daemon: Interface eth0 link up - 1000mbps", "color": "var(--text-muted)" },
                        { "type": "WARN", "msg": "auth_daemon: SSH login failed for invalid user root from 185.220.101.4", "color": "var(--secondary)" },
                        { "type": "INFO", "msg": "sqlite3: connection pool initialized (8 threads)", "color": "var(--text-muted)" },
                    ]
                    tpl = random.choice(syslog_templates)
                    log_entries.append({
                        "text": f"[{tpl['type']}] {tpl['msg']}",
                        "color": tpl['color']
                    })
                    
                await websocket.send_json({
                    "type": "telemetry",
                    "cpu": round(cpu, 1),
                    "memory": round(memory, 1),
                    "latency": round(latency, 1),
                    "logs": log_entries
                })
            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(1.0)

# Legacy /stream-telemetry SSE endpoint
@app.get("/stream-telemetry")
async def stream_telemetry():
    async def generate_stream():
        sent_logs = set()
        iterations = 0
        while True:
            if "pytest" in sys.modules and iterations >= 2:
                break
            iterations += 1
            
            container_name = get_active_sandbox_container()
            if container_name:
                stats = get_sandbox_stats(container_name)
                cpu = stats.get("cpu", 0.0)
                memory = stats.get("memory", 0.0)
                cpu = max(0.0, min(100.0, cpu + random.uniform(-0.5, 0.5)))
                memory = max(0.0, min(100.0, memory + random.uniform(-0.2, 0.2)))
                latency = random.uniform(2.0, 5.0)
                
                logs = get_sandbox_logs(container_name, tail=15)
                log_entries = []
                for line in logs:
                    if line not in sent_logs:
                        sent_logs.add(line)
                        if "GET " in line or "POST " in line:
                            match = re.search(r'"(GET|POST|PUT|DELETE)\s+([^\s?]+)(\?[^\s"]*)?\s+HTTP', line)
                            if match:
                                method = match.group(1)
                                route = match.group(2)
                                params = match.group(3) or ""
                                ip_match = re.match(r'^([0-9.]+)', line)
                                src_ip = ip_match.group(1) if ip_match else "172.17.0.1"
                                status_match = re.search(r'HTTP/[0-9.]+"\s+(\d+)', line)
                                status = status_match.group(1) if status_match else "200"
                                log_entries.append({
                                    "text": f"[PACKET] INBOUND TCP: Src={src_ip} Dst=127.0.0.1:5001 | {method} {route}{params} [Status={status}]",
                                    "color": "var(--primary)" if status != "403" else "var(--secondary)"
                                })
                            else:
                                log_entries.append({
                                    "text": f"[INFO] container: {line}",
                                    "color": "var(--text-muted)"
                                })
                        else:
                            log_entries.append({
                                "text": f"[INFO] container: {line}",
                                "color": "var(--text-muted)"
                            })

            else:
                cpu = max(5.0, min(95.0, 12.5 + random.uniform(-2.0, 2.0)))
                memory = max(5.0, min(95.0, 34.2 + random.uniform(-0.5, 0.5)))
                latency = max(1.0, min(5000.0, 15.0 + random.uniform(-1.0, 1.0)))
                log_entries = []
                if random.random() < 0.2:
                    syslog_templates = [
                        { "type": "INFO", "msg": "kernel: CPU temperature nominal (39C)", "color": "var(--text-muted)" },
                        { "type": "OK", "msg": "cron: PID 4519 - ran job: clean_tmp_downloads", "color": "var(--text-muted)" },
                        { "type": "INFO", "msg": "net_daemon: Interface eth0 link up - 1000mbps", "color": "var(--text-muted)" },
                        { "type": "WARN", "msg": "auth_daemon: SSH login failed for invalid user root from 185.220.101.4", "color": "var(--secondary)" },
                        { "type": "INFO", "msg": "sqlite3: connection pool initialized (8 threads)", "color": "var(--text-muted)" },
                    ]
                    tpl = random.choice(syslog_templates)
                    log_entries.append({
                        "text": f"[{tpl['type']}] {tpl['msg']}",
                        "color": tpl['color']
                    })

            payload = {
                "cpu": round(cpu, 1),
                "memory": round(memory, 1),
                "latency": round(latency, 1),
                "logs": log_entries
            }
            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(1.0)
            
    return StreamingResponse(generate_stream(), media_type="text/event-stream")

@app.get("/health")
def health():
    return {
        "status": "running",
        "service": "aegis-vulnerable-demo"
    }

@app.get("/user")
def get_user(name: str = "guest"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT id, username, role, api_key FROM users WHERE username = '{name}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return {
        "query": query,
        "results": rows
    }

@app.get("/ping")
def ping_host(host: str = "127.0.0.1"):
    command = f"ping -c 1 {host}"
    output = subprocess.check_output(command, shell=True, text=True)
    return {
        "command": command,
        "output": output
    }

@app.get("/calculate")
def calculate(expr: str = "1+1"):
    result = eval(expr)
    return {
        "expression": expr,
        "result": result
    }

@app.post("/load-profile")
async def load_profile(request: Request):
    body = await request.json()
    encoded_profile = body.get("profile", "")
    raw_data = base64.b64decode(encoded_profile)
    profile = pickle.loads(raw_data)
    return {
        "loaded_profile": str(profile)
    }

@app.get("/download")
def download_file(file: str = "sample.txt"):
    target_file = DOWNLOAD_DIR / file
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return PlainTextResponse(target_file.read_text())

@app.get("/hash")
def weak_hash(value: str = "password123"):
    digest = hashlib.md5(value.encode()).hexdigest()
    return {
        "value": value,
        "md5": digest
    }

@app.get("/xss", response_class=HTMLResponse)
def xss_demo(msg: str = "Welcome to Aegis console."):
    return f"<html><body><div id='xss-output'>{msg}</div></body></html>"

@app.get("/ssrf")
def ssrf_demo(url: str = "http://127.0.0.1:5001/health"):
    import urllib.request
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Aegis-Simulated-Scanner/2.0'}
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return {
                "url": url,
                "status": "success",
                "response": content[:1000]
            }
    except Exception as e:
        return {
            "url": url,
            "status": "error",
            "message": str(e)
        }

@app.get("/debug-info")
def debug_info():
    return {
        "database_password": DATABASE_PASSWORD,
        "aws_access_key": AWS_ACCESS_KEY_ID,
        "environment": dict(os.environ)
    }

@app.get("/export-dossier")
def export_dossier():
    def load_json(path):
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except Exception:
            return None

    ruff_report = load_json(SCANS_DIR / "ruff-report.json")
    safety_report = load_json(SCANS_DIR / "safety-report.json")
    trivy_report = load_json(SCANS_DIR / "trivy-report.json")
    secrets_report = load_json(SCANS_DIR / "secrets-report.json")
    yara_report = load_json(SCANS_DIR / "yara-report.json")
    semgrep_report = load_json(SCANS_DIR / "semgrep-report.json")
    clamav_report = load_json(SCANS_DIR / "clamav-report.json")
    zap_report = load_json(SCANS_DIR / "zap-report.json")

    # Ruff (SAST)
    if not (SCANS_DIR / "ruff-report.json").exists():
        ruff_status = "MISSING"
        ruff_total = 0
        ruff_blocking = 0
    else:
        ruff_results = ruff_report if isinstance(ruff_report, list) else []
        ruff_total = len(ruff_results)
        ruff_blocking = len([r for r in ruff_results if get_ruff_severity(r.get("code", "UNKNOWN")) in {"MEDIUM", "HIGH"}])
        ruff_status = "FAIL" if ruff_blocking > 0 else "PASS"

    # Semgrep
    if not (SCANS_DIR / "semgrep-report.json").exists():
        semgrep_status = "MISSING"
        semgrep_total = 0
        semgrep_blocking = 0
    else:
        semgrep_results = semgrep_report.get("results", []) if semgrep_report else []
        semgrep_total = len(semgrep_results)
        semgrep_blocking = len([r for r in semgrep_results if r.get("extra", {}).get("severity", "").upper() in {"ERROR", "WARNING"}])
        semgrep_status = "FAIL" if semgrep_blocking > 0 else "PASS"

    # Safety
    if not (SCANS_DIR / "safety-report.json").exists():
        safety_status = "MISSING"
        safety_total = 0
        safety_blocking = 0
    else:
        safety_vulns = []
        if isinstance(safety_report, dict):
            safety_vulns = safety_report.get("vulnerabilities", []) or safety_report.get("results", [])
        elif isinstance(safety_report, list):
            safety_vulns = safety_report
        safety_total = len(safety_vulns)
        safety_blocking = safety_total
        safety_status = "FAIL" if safety_blocking > 0 else "PASS"

    # Trivy
    if not (SCANS_DIR / "trivy-report.json").exists():
        trivy_status = "MISSING"
        trivy_total = 0
        trivy_blocking = 0
    else:
        trivy_vulns = []
        for result in (trivy_report.get("Results", []) or []):
            for vulnerability in result.get("Vulnerabilities", []) or []:
                trivy_vulns.append(vulnerability)
        trivy_total = len(trivy_vulns)
        trivy_blocking = len([v for v in trivy_vulns if v.get("Severity", "").upper() in {"MEDIUM", "HIGH", "CRITICAL"}])
        trivy_status = "FAIL" if trivy_blocking > 0 else "PASS"

    # Secrets
    if not (SCANS_DIR / "secrets-report.json").exists():
        secrets_status = "MISSING"
        secrets_total = 0
        secrets_blocking = 0
    else:
        secrets_results = secrets_report.get("results", {}) or {} if secrets_report else {}
        secrets_findings = []
        for filename, file_secrets in secrets_results.items():
            for secret in file_secrets:
                secrets_findings.append(secret)
        secrets_total = len(secrets_findings)
        secrets_blocking = secrets_total
        secrets_status = "FAIL" if secrets_blocking > 0 else "PASS"

    # YARA
    if not (SCANS_DIR / "yara-report.json").exists():
        yara_status = "MISSING"
        yara_total = 0
        yara_blocking = 0
    else:
        yara_findings = yara_report if isinstance(yara_report, list) else []
        yara_total = len(yara_findings)
        yara_blocking = yara_total
        yara_status = "FAIL" if yara_blocking > 0 else "PASS"

    # ClamAV
    if not (SCANS_DIR / "clamav-report.json").exists():
        clamav_status = "MISSING"
        clamav_total = 0
        clamav_blocking = 0
    else:
        clamav_findings_list = clamav_report if isinstance(clamav_report, list) else []
        clamav_total = len(clamav_findings_list)
        clamav_blocking = clamav_total
        clamav_status = "FAIL" if clamav_blocking > 0 else "PASS"

    # ZAP DAST
    if not (SCANS_DIR / "zap-report.json").exists():
        zap_status = "MISSING"
        zap_total = 0
        zap_blocking = 0
    else:
        zap_findings_list = zap_report if isinstance(zap_report, list) else []
        zap_total = len(zap_findings_list)
        zap_blocking = len([f for f in zap_findings_list if f.get("status") == "EXPOSED"])
        zap_status = "FAIL" if zap_blocking > 0 else "PASS"

    # Decision
    failed_tools = []
    missing_tools = []
    for tool, status in [
        ("Ruff (SAST)", ruff_status),
        ("Semgrep", semgrep_status),
        ("Safety", safety_status),
        ("Trivy", trivy_status),
        ("Secrets Scanner", secrets_status),
        ("YARA Scanner", yara_status),
        ("ClamAV Antivirus", clamav_status),
        ("OWASP ZAP DAST", zap_status)
    ]:
        if status == "FAIL":
            failed_tools.append(tool)
        elif status == "MISSING":
            missing_tools.append(tool)

    if failed_tools or missing_tools:
        gate_decision = "BLOCKED"
        reasons = []
        if failed_tools:
            reasons.append(f"Blocking security issues found by: {', '.join(failed_tools)}")
        if missing_tools:
            reasons.append(f"Required scan reports missing for: {', '.join(missing_tools)}")
        reason = " | ".join(reasons)
    else:
        gate_decision = "ALLOWED"
        reason = "No blocking security issues found."

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Format Ruff
    ruff_findings = ""
    if ruff_report and isinstance(ruff_report, list):
        for issue in ruff_report[:5]:
            code = issue.get('code', 'UNKNOWN')
            severity = get_ruff_severity(code)
            ruff_findings += f"  - ID: {code} | Severity: {severity}\n"
            ruff_findings += f"    Location: {issue.get('filename')}:{issue.get('location', {}).get('row')}\n"
            ruff_findings += f"    Details: {issue.get('message')}\n"
            ruff_findings += "  ------------------------------------------------------------------\n"
    else:
        ruff_findings = "  No issues detected.\n"

    # Format Semgrep
    semgrep_findings = ""
    if semgrep_report and semgrep_report.get("results"):
        for issue in semgrep_report.get("results", [])[:5]:
            extra = issue.get("extra", {})
            semgrep_findings += f"  - ID: {issue.get('check_id')} | Severity: {extra.get('severity')}\n"
            semgrep_findings += f"    Location: {issue.get('path')}:{issue.get('start', {}).get('line')}\n"
            semgrep_findings += f"    Details: {extra.get('message')}\n"
            code = extra.get('lines', '')
            if code:
                code_lines = code.strip().split('\n')
                semgrep_findings += f"    Source:\n"
                for cl in code_lines[:3]:
                    semgrep_findings += f"      >> {cl}\n"
            semgrep_findings += "  ------------------------------------------------------------------\n"
    else:
        semgrep_findings = "  No issues detected.\n"

    # Format Safety
    safety_findings = ""
    if safety_report:
        vulns = []
        if isinstance(safety_report, dict):
            vulns = safety_report.get("vulnerabilities", []) or safety_report.get("results", [])
        elif isinstance(safety_report, list):
            vulns = safety_report
        
        if vulns:
            for v in vulns[:5]:
                pkg = v.get("package_name") or v.get("package")
                vuln_id = v.get("vulnerability_id") or v.get("advisory")
                affected = v.get("affected_versions") or v.get("version")
                fixed = v.get("fixed_versions") or v.get("fixed")
                desc = v.get("description") or v.get("reason", "No description provided.")
                safety_findings += f"  - Package: {pkg} | ID: {vuln_id}\n"
                safety_findings += f"    Affected: {affected} | Fixed: {fixed}\n"
                safety_findings += f"    Description: {desc[:120]}...\n"
                safety_findings += "  ------------------------------------------------------------------\n"
        else:
            safety_findings = "  No issues detected.\n"
    else:
        safety_findings = "  No report file found.\n"

    # Format Trivy
    trivy_findings = ""
    if trivy_report:
        trivy_vulns = []
        for result in trivy_report.get("Results", []) or []:
            for vulnerability in result.get("Vulnerabilities", []) or []:
                trivy_vulns.append({
                    "target": result.get("Target"),
                    "vulnerability_id": vulnerability.get("VulnerabilityID"),
                    "package_name": vulnerability.get("PkgName"),
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "severity": vulnerability.get("Severity", "").upper(),
                    "title": vulnerability.get("Title"),
                })
        if trivy_vulns:
            for v in trivy_vulns[:5]:
                trivy_findings += f"  - Target: {v.get('target')} | Package: {v.get('package_name')} | ID: {v.get('vulnerability_id')}\n"
                trivy_findings += f"    Severity: {v.get('severity')} | Installed: {v.get('installed_version')} | Fixed: {v.get('fixed_version')}\n"
                trivy_findings += f"    Title: {v.get('title')}\n"
                trivy_findings += "  ------------------------------------------------------------------\n"
        else:
            trivy_findings = "  No issues detected.\n"
    else:
        trivy_findings = "  No report file found.\n"

    # Format Secrets
    secrets_findings = ""
    if secrets_report:
        secrets_results = secrets_report.get("results", {}) or {}
        secrets_list = []
        for filename, file_secrets in secrets_results.items():
            for secret in file_secrets:
                secrets_list.append({
                    "type": secret.get("type"),
                    "filename": filename,
                    "line_number": secret.get("line_number")
                })
        if secrets_list:
            for s in secrets_list[:5]:
                secrets_findings += f"  - Type: {s.get('type')}\n"
                secrets_findings += f"    Location: {s.get('filename')}:{s.get('line_number')}\n"
                secrets_findings += "  ------------------------------------------------------------------\n"
        else:
            secrets_findings = "  No secrets detected.\n"
    else:
        secrets_findings = "  No report file found.\n"

    # Format YARA
    yara_findings_text = ""
    if yara_report:
        yara_list = yara_report if isinstance(yara_report, list) else []
        if yara_list:
            for y in yara_list[:5]:
                yara_findings_text += f"  - Rule matched: {y.get('rule')}\n"
                yara_findings_text += f"    Target File: {y.get('filename')}\n"
                yara_findings_text += f"    Description: {y.get('description')}\n"
                yara_findings_text += "  ------------------------------------------------------------------\n"
        else:
            yara_findings_text = "  No malicious signatures matched.\n"
    else:
        yara_findings_text = "  No report file found.\n"

    # Format ClamAV
    clamav_findings_text = ""
    if clamav_report:
        clamav_list = clamav_report if isinstance(clamav_report, list) else []
        if clamav_list:
            for c in clamav_list[:5]:
                clamav_findings_text += f"  - Virus matched: {c.get('virus')}\n"
                clamav_findings_text += f"    Target File: {c.get('filename')}\n"
                clamav_findings_text += f"    Description: {c.get('description')}\n"
                clamav_findings_text += "  ------------------------------------------------------------------\n"
        else:
            clamav_findings_text = "  No malware signatures matched.\n"
    else:
        clamav_findings_text = "  No report file found.\n"

    # Format ZAP
    zap_findings_text = ""
    if zap_report:
        zap_list = zap_report if isinstance(zap_report, list) else []
        if zap_list:
            for z in zap_list[:6]:
                zap_findings_text += f"  - Vulnerability: {z.get('vuln_type')} | Status: {z.get('status')}\n"
                zap_findings_text += f"    Route: {z.get('route')} | Payload: {z.get('payload')}\n"
                zap_findings_text += f"    Description: {z.get('description')}\n"
                zap_findings_text += "  ------------------------------------------------------------------\n"
        else:
            zap_findings_text = "  No active DAST endpoints scanned.\n"
    else:
        zap_findings_text = "  No report file found.\n"

    dossier_text = f"""================================================================================
  █████╗ ███████╗ ██████╗ ██╗███████╗
 ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
 ███████║█████╗  ██║  ███╗██║███████╗
 ██╔══██║██╔══╝  ██║   ██║██║╚════██║
 ██║  ██║███████╗╚██████╔╝██║███████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
       AEGIS DEVSECOPS COMPLIANCE DOSSIER
================================================================================
TIMESTAMP: {timestamp}
GATE DECISION: {gate_decision}
REASON: {reason}
================================================================================

[1] PYTHON SECURITY LINTER - RUFF (SAST)
--------------------------------------------------------------------------------
Status: {ruff_status}
Total Issues Detected: {ruff_total}
Blocking Issues: {ruff_blocking}

FINDINGS (Top 5):
{ruff_findings}

[1.5] ADVANCED STATIC ANALYSIS ENGINE - SEMGREP
--------------------------------------------------------------------------------
Status: {semgrep_status}
Total Issues Detected: {semgrep_total}
Blocking Issues: {semgrep_blocking}

FINDINGS (Top 5):
{semgrep_findings}

[2] SOFTWARE COMPOSITION ANALYSIS (SCA) - SAFETY
--------------------------------------------------------------------------------
Status: {safety_status}
Total Issues Detected: {safety_total}
Blocking Issues: {safety_blocking}

FINDINGS (Top 5):
{safety_findings}

[3] CONTAINER IMAGE SCANNING - TRIVY
--------------------------------------------------------------------------------
Status: {trivy_status}
Total Issues Detected: {trivy_total}
Blocking Issues: {trivy_blocking}

FINDINGS (Top 5):
{trivy_findings}

[4] SECRET SCANNER - DETECT-SECRETS
--------------------------------------------------------------------------------
Status: {secrets_status}
Total Issues Detected: {secrets_total}
Blocking Issues: {secrets_blocking}

FINDINGS (Top 5):
{secrets_findings}

[5] MALWARE & BACKDOOR SIGNATURES - YARA
--------------------------------------------------------------------------------
Status: {yara_status}
Total Issues Detected: {yara_total}
Blocking Issues: {yara_blocking}

FINDINGS (Top 5):
{yara_findings_text}

[6] MALWARE SIGNATURE ANALYSIS - CLAMAV
--------------------------------------------------------------------------------
Status: {clamav_status}
Total Issues Detected: {clamav_total}
Blocking Issues: {clamav_blocking}

FINDINGS (Top 5):
{clamav_findings_text}

[7] DYNAMIC APPLICATION SECURITY TESTING (DAST) - OWASP ZAP
--------------------------------------------------------------------------------
Status: {zap_status}
Total Issues Detected: {zap_total}
Blocking Issues: {zap_blocking}

FINDINGS:
{zap_findings_text}

================================================================================
                    [ END OF SECURE TRANSMISSION ]
================================================================================
"""
    return Response(
        content=dossier_text,
        media_type="text/plain",
        headers={
            "Content-Disposition": "attachment;filename=aegis-compliance-dossier.txt"
        }
    )

if __name__ == "__main__":
    import uvicorn
    initialize_database()
    uvicorn.run("main:app", host="0.0.0.0", port=5001, reload=False)
