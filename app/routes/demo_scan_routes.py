import asyncio
import json
import logging
import os
import random
import re
import sys
import time
import uuid

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from starlette.datastructures import UploadFile
from werkzeug.utils import secure_filename

from ..auth import require_role, websocket_principal
from ..database import (
    PROJECT_ROOT,
    REDIS_AVAILABLE,
    REDIS_URL,
    SCANS_DIR,
    redis_client,
    set_application_state,
)
from ..rate_limit import allow_websocket
from ..reporting import (
    calculate_exploitability_score,
    load_dependency_tree,
    load_json_report,
)
from ..sandbox import (
    get_active_sandbox_container,
    get_sandbox_logs,
    get_sandbox_stats,
)
from ..scan_engine import ScanJobPayload
from ..version import get_package_version
from ..projects import require_project_role
from ..waf_rules import save_waf_rules as save_waf_rules_to_db
from ..web_common import (
    ALLOWED_SCAN_TARGETS,
    COMMERCIAL_CONTACT_URL,
    MAX_UPLOAD_BYTES,
    SCAN_JOB_TIMEOUT_SECONDS,
    load_waf_rules_from_db,
    require_access,
    require_demo_boundary,
    require_demo_lab_access,
    require_recent_access,
    setup_is_available,
    templates,
)
from policy_engine import analyze_report_set, evaluate_policy_results
from .. import web_common

router = APIRouter()
logger = logging.getLogger("aegis.main")


@router.get("/lab", response_class=HTMLResponse)
def threat_lab(request: Request, _principal=Depends(require_demo_lab_access)):
    """Keep the intentionally theatrical demo surface separate from project work."""
    if setup_is_available():
        return RedirectResponse("/setup", status_code=303)
    return templates.TemplateResponse(request, "index.html", {"threat_lab": True})


@router.get("/welcome", response_class=HTMLResponse)
def commercial_landing(request: Request):
    """Public product page for visitors who are not ready to sign in."""
    return templates.TemplateResponse(
        request,
        "landing.html",
        {
            "pilot_url": COMMERCIAL_CONTACT_URL,
            "github_url": "https://github.com/huslenine999/aegis",
        },
    )

@router.post(
    "/toggle-waf",
    dependencies=[Depends(require_demo_boundary), Depends(require_recent_access("admin"))],
)
def toggle_waf():
    web_common.WAF_ENABLED = not web_common.WAF_ENABLED
    set_application_state("waf_enabled", web_common.WAF_ENABLED)
    return {"status": "success", "waf_enabled": web_common.WAF_ENABLED}

@router.get(
    "/get-waf-rules",
    dependencies=[Depends(require_demo_boundary), Depends(require_role("viewer"))],
)
def get_waf_rules():
    rules = load_waf_rules_from_db()
    return {"status": "success", "rules": rules, "waf_enabled": web_common.WAF_ENABLED}

@router.post(
    "/save-waf-rules",
    dependencies=[Depends(require_demo_boundary), Depends(require_recent_access("admin"))],
)
async def save_waf_rules(request: Request):
    try:
        data = await request.json()
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise HTTPException(status_code=400, detail="WAF rules must be a list.")
        if len(rules) > 100:
            raise HTTPException(status_code=400, detail="At most 100 WAF rules are allowed.")
        new_rules = []
        for r in rules:
            if not isinstance(r, dict):
                raise HTTPException(status_code=400, detail="Each WAF rule must be an object.")
            if "pattern" in r:
                pattern = str(r["pattern"])
                if len(pattern) > 256:
                    raise HTTPException(status_code=400, detail="WAF rule pattern is too long.")
                description = str(r.get("description", ""))
                if len(description) > 512:
                    raise HTTPException(status_code=400, detail="WAF rule description is too long.")
                try:
                    re.compile(pattern)
                except re.error as e:
                    raise HTTPException(status_code=400, detail=f"Invalid WAF rule regex: {e}")
                new_rules.append({
                    "pattern": pattern,
                    "description": description,
                    "enabled": bool(r.get("enabled", True))
                })
        save_waf_rules_to_db(new_rules)
        return {"status": "success", "message": "WAF rules updated successfully."}
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unable to persist WAF rules")
        raise HTTPException(
            status_code=500, detail="Unable to persist WAF rules. Check server logs."
        )

@router.get(
    "/get-scan-results",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def get_scan_results():
    clamav = load_json_report(SCANS_DIR / "clamav-report.json")
    zap = load_json_report(SCANS_DIR / "zap-report.json")
    osv = load_json_report(SCANS_DIR / "osv-report.json")
    ruff = load_json_report(SCANS_DIR / "ruff-report.json")
    semgrep = load_json_report(SCANS_DIR / "semgrep-report.json")
    safety = load_json_report(SCANS_DIR / "safety-report.json")
    trivy = load_json_report(SCANS_DIR / "trivy-report.json")
    secrets = load_json_report(SCANS_DIR / "secrets-report.json")
    yara = load_json_report(SCANS_DIR / "yara-report.json")
    iac = load_json_report(SCANS_DIR / "iac-report.json")
    
    score = calculate_exploitability_score(SCANS_DIR, web_common.WAF_ENABLED)
    
    has_run = any(report is not None for report in [ruff, semgrep, osv, safety, trivy, secrets, yara, clamav, zap, iac])
    results = analyze_report_set({
        "ruff": ruff,
        "semgrep": semgrep,
        "safety": safety,
        "osv": osv,
        "trivy": trivy,
        "secrets": secrets,
        "yara": yara,
        "clamav": clamav,
        "zap": zap,
        "iac": iac,
    })
    decision = evaluate_policy_results(results)
    is_blocked = has_run and decision["status"] != "ALLOWED"
    reasons = [
        *decision["error_tools"],
        *decision["failed_tools"],
        *decision["missing_tools"],
    ]

    latest_report = SCANS_DIR / "report.html"
    latest_scan_time = None
    if latest_report.exists():
        latest_scan_time = latest_report.stat().st_mtime

    sandbox_status_file = SCANS_DIR / "sandbox-status.json"
    sandbox_status = "simulated_fallback"
    sandbox_report = load_json_report(sandbox_status_file)
    if isinstance(sandbox_report, dict):
        sandbox_status = sandbox_report.get("status", "simulated_fallback")

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
        "iac": iac,
        "exploitability_score": score,
        "waf_enabled": web_common.WAF_ENABLED,
        "has_run": has_run,
        "is_blocked": is_blocked,
        "blocked_by": reasons,
        "decision": decision["status"],
        "decision_reason": decision["reason"],
        "error_tools": decision["error_tools"],
        "sandbox_status": sandbox_status,
        "latest_scan_time": latest_scan_time,
        "report_url": "/report" if latest_report.exists() else None,
        "markdown_url": "/export-dossier" if latest_report.exists() else None,
        "sbom_url": "/download-sbom" if (SCANS_DIR / "sbom.json").exists() else None,
        "bundle_url": "/download-report-bundle" if latest_report.exists() else None
    }

@router.get(
    "/get-dependency-graph",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def get_dependency_graph():
    vulnerable_packages = set()
    report = load_json_report(SCANS_DIR / "safety-report.json")
    if isinstance(report, dict) and "vulnerabilities" in report:
        for vulnerability in report["vulnerabilities"]:
            package = vulnerability.get("package_name") or vulnerability.get("package")
            if package:
                vulnerable_packages.add(package.lower())
    elif isinstance(report, list):
        for vulnerability in report:
            package = vulnerability.get("package_name") or vulnerability.get("package")
            if package:
                vulnerable_packages.add(package.lower())
    elif isinstance(report, dict) and "affected_packages" in report:
        vulnerable_packages.update(
            package.lower() for package in report["affected_packages"]
        )

    osv_vulnerabilities: dict[str, list[dict]] = {}
    osv_findings = load_json_report(SCANS_DIR / "osv-report.json")
    if isinstance(osv_findings, list):
        for finding in osv_findings:
            package = finding.get("package")
            if package:
                osv_vulnerabilities.setdefault(package.lower(), []).append({
                    "id": finding.get("id"),
                    "cvss": finding.get("cvss"),
                    "summary": finding.get("summary"),
                })

    raw_tree = load_dependency_tree(PROJECT_ROOT)

    nodes = {}
    links: list[dict] = []
    
    nodes["aegis"] = {
        "id": "aegis",
        "name": "Aegis (Root)",
        "installed_version": get_package_version(),
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
            
            if link_key not in [(link["source"], link["target"]) for link in links]:
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

@router.post("/run-scan", dependencies=[Depends(require_demo_boundary)])
async def run_scan(request: Request, principal=Depends(require_access("operator"))):
    if os.environ.get("VERCEL"):
        raise HTTPException(status_code=400, detail="Security scans are not supported in the Vercel serverless environment.")

    content_type = request.headers.get("content-type", "")
    uploaded_file = None
    uploaded_filename = None
    target_name = "vulnerable"

    if "multipart/form-data" in content_type:
        form = await request.form()
        form_file = form.get("file")
        if isinstance(form_file, UploadFile):
            uploaded_file = form_file
            uploaded_filename = uploaded_file.filename
    else:
        try:
            body = await request.json()
            target_name = body.get("target", "vulnerable")
        except Exception:
            try:
                form = await request.form()
                form_target = form.get("target", "vulnerable")
                if isinstance(form_target, str):
                    target_name = form_target
            except Exception:
                pass

    if not isinstance(target_name, str) or target_name not in ALLOWED_SCAN_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan target. Choose one of: {', '.join(sorted(ALLOWED_SCAN_TARGETS))}.",
        )

    custom_file_path = None
    if uploaded_file and uploaded_filename:
        if not uploaded_filename.lower().endswith('.py'):
            raise HTTPException(status_code=400, detail="Invalid file type. Only Python (.py) files are allowed.")
        safe_filename = secure_filename(uploaded_filename)
        if not safe_filename:
            raise HTTPException(status_code=400, detail="Invalid upload filename.")
        contents = await uploaded_file.read(MAX_UPLOAD_BYTES + 1)
        if len(contents) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Upload exceeds the {MAX_UPLOAD_BYTES}-byte limit.",
            )
        uuid_str = uuid.uuid4().hex
        temp_dir = SCANS_DIR / "uploads" / uuid_str
        temp_dir.mkdir(exist_ok=True, parents=True)
        temp_filepath = temp_dir / safe_filename
        temp_filepath.write_bytes(contents)
        custom_file_path = str(temp_filepath)

    job_id = uuid.uuid4().hex
    
    # Write initial job status in Redis hash
    redis_client.hset(
        f"job:{job_id}",
        mapping={
            "state": "queued",
            "progress": 0,
            "owner_id": principal.user_id,
            "queued_at": time.time(),
        },
    )

    # Import worker task logic
    from ..worker import async_scan_task

    payload = ScanJobPayload(
        job_id=job_id,
        target=target_name,
        custom_file_path=custom_file_path,
        waf_enabled=web_common.WAF_ENABLED,
    )

    if REDIS_AVAILABLE:
        from rq import Queue
        from redis import Redis

        r_conn = Redis.from_url(REDIS_URL)
        q = Queue(connection=r_conn)
        q.enqueue(
            async_scan_task,
            payload,
            job_timeout=SCAN_JOB_TIMEOUT_SECONDS,
        )
    else:
        import threading
        # Run scan task in a background thread in-process
        thread = threading.Thread(
            target=async_scan_task,
            args=(payload,)
        )
        thread.daemon = True
        thread.start()

    return {
        "status": "success",
        "job_id": job_id,
        "state": "queued"
    }

@router.websocket("/ws/scan/{job_id}")
async def websocket_scan(websocket: WebSocket, job_id: str):
    """Stream an authorized product scan; demo-lab guards do not apply here."""
    principal = websocket_principal(websocket, "viewer")
    if not principal:
        await websocket.close(code=4401, reason="Authentication required")
        return
    address = websocket.client.host if websocket.client else "unknown"
    if not allow_websocket(redis_client, address):
        await websocket.close(code=4429, reason="Rate limit exceeded")
        return
    owner = redis_client.hget(f"job:{job_id}", "owner_id")
    if not owner:
        await websocket.close(code=4404, reason="Scan job not found")
        return
    owner_id = int(owner.decode() if isinstance(owner, bytes) else owner)
    project_value = redis_client.hget(f"job:{job_id}", "project_id")
    if project_value:
        project_id = int(
            project_value.decode() if isinstance(project_value, bytes) else project_value
        )
        try:
            require_project_role(
                project_id,
                principal.user_id,
                principal.role,
                "viewer",
                principal.tenant_id,
            )
        except PermissionError:
            await websocket.close(code=4403, reason="Scan job access denied")
            return
    elif owner_id != principal.user_id:
        await websocket.close(code=4403, reason="Scan job access denied")
        return
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
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("Ignoring malformed stored job log for %s: %s", job_id, exc)
            
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
    metrics_task = asyncio.create_task(stream_telemetry_metrics_ws(websocket, job_id))
    
    try:
        while True:
            # Non-blocking poll for pubsub messages
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if message:
                data = json.loads(message['data'].decode('utf-8'))
                await websocket.send_json(data)
                if data.get("type") == "state" and data.get("state") in ("completed", "failed", "cancelled"):
                    break
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        metrics_task.cancel()
        pubsub.unsubscribe(f"job_channel:{job_id}")
        pubsub.close()

def _job_sandbox_container(job_id: str) -> str | None:
    value = redis_client.hget(f"job:{job_id}", "sandbox_container_id")
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    if not isinstance(value, str) or not value:
        return None
    if not value.startswith("aegis-sandbox-container-"):
        return None
    return value


async def stream_telemetry_metrics_ws(websocket: WebSocket, job_id: str):
    sent_logs = set()
    import random
    
    while True:
        try:
            container_name = _job_sandbox_container(job_id)
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
        except Exception as exc:
            logger.debug("Legacy telemetry sample failed: %s", exc)
            await asyncio.sleep(1.0)

# Legacy /stream-telemetry SSE endpoint
@router.get("/stream-telemetry", dependencies=[Depends(require_demo_boundary)])
async def stream_telemetry(principal=Depends(require_access("admin"))):
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
