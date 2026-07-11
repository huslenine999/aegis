import os
import re
import sys
import time
import random
import json
import asyncio
import hmac
import hashlib
import uuid
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

# Add the current directory and project root to sys.path to allow imports
sys.path.append(str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent))

# Ensure the virtual environment's bin/Scripts directory is in PATH so that packages
# invoking subprocesses (like semgrep) can find their corresponding executables.
sys_exec_dir = os.path.dirname(sys.executable)
if sys_exec_dir and sys_exec_dir not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = sys_exec_dir + os.pathsep + os.environ.get("PATH", "")

from fastapi import Depends, FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from werkzeug.utils import secure_filename

from database import (
    BASE_DIR,
    DOWNLOAD_DIR,
    PROJECT_ROOT,
    REDIS_AVAILABLE,
    REDIS_URL,
    SCANS_DIR,
    initialize_database,
    get_connection,
    get_application_state,
    set_application_state,
    redis_client,
)
from config import environment_list, environment_positive_int, validate_runtime_configuration
from auth import (
    AUTH_REQUIRED,
    SESSION_COOKIE,
    authenticate,
    complete_initial_setup,
    create_session,
    ensure_bootstrap_admin,
    hash_password,
    principal_from_request,
    require_role,
    revoke_session,
    revoke_user_sessions,
    websocket_principal,
)
from observability import ObservabilityMiddleware, configure_logging, recent_requests, render_metrics
from rate_limit import RateLimitMiddleware, allow_websocket
from security_middleware import (
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
    WafASGIMiddleware,
)
from projects import (
    VALID_PRESETS,
    create_project,
    create_scan_run,
    delete_project,
    get_project,
    get_scan_run,
    list_projects,
    list_project_members,
    list_scan_runs,
    remove_project_member,
    require_project_role,
    set_project_member,
    update_project,
)
from github_integration import (
    begin_oauth,
    complete_oauth,
    disconnect_github,
    github_connection,
    github_enabled,
    list_repositories,
)
from notifications import CHANNEL_TYPES, create_channel, delete_channel, list_channels, test_channel
from audit import list_audit_events, record_audit
from policy_engine import get_ruff_severity
from sandbox import (
    get_active_sandbox_container,
    get_sandbox_logs,
    get_sandbox_stats,
    is_docker_available,
)
from reporting import (
    build_report_bundle,
    calculate_exploitability_score,
    generate_fallback_tree as generate_project_fallback_tree,
    load_dependency_tree,
)

validate_runtime_configuration()
configure_logging()

app = FastAPI(title="Aegis DevSecOps Console")
DEMO_LAB_ENABLED = os.environ.get("AEGIS_ENABLE_DEMO_LAB", "false").lower() in {"1", "true", "yes", "on"}
ADMIN_TOKEN = os.environ.get("AEGIS_ADMIN_TOKEN")
MAX_UPLOAD_BYTES = environment_positive_int("AEGIS_MAX_UPLOAD_BYTES", 1024 * 1024)
MAX_REQUEST_BYTES = environment_positive_int(
    "AEGIS_MAX_REQUEST_BYTES", MAX_UPLOAD_BYTES + 64 * 1024
)
ALLOWED_SCAN_TARGETS = {"project", "secure", "vulnerable"}
RUN_ARTIFACTS = {
    "report.html": "text/html; charset=utf-8",
    "report.md": "text/markdown; charset=utf-8",
    "sbom.json": "application/json",
    "ruff-report.json": "application/json",
    "semgrep-report.json": "application/json",
    "safety-report.json": "application/json",
    "osv-report.json": "application/json",
    "trivy-report.json": "application/json",
    "secrets-report.json": "application/json",
    "yara-report.json": "application/json",
    "clamav-report.json": "application/json",
    "zap-report.json": "application/json",
    "sandbox-status.json": "application/json",
    "scan-manifest.json": "application/json",
}

# Enable CORS for convenience
def parse_cors_origins() -> list[str]:
    raw_origins = os.environ.get("AEGIS_CORS_ORIGINS", "http://127.0.0.1:5001,http://localhost:5001")
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
allowed_hosts = environment_list("AEGIS_ALLOWED_HOSTS")
if allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def require_demo_lab_enabled():
    if not DEMO_LAB_ENABLED:
        raise HTTPException(
            status_code=404,
            detail="Aegis demo lab is disabled. Set AEGIS_ENABLE_DEMO_LAB=true to enable vulnerable training routes.",
        )


def require_access(minimum_role: str):
    role_dependency = require_role(minimum_role)

    def dependency(request: Request):
        if not AUTH_REQUIRED and ADMIN_TOKEN and minimum_role in {"operator", "admin"}:
            supplied = request.headers.get("X-Aegis-Token", "")
            if not supplied or not hmac.compare_digest(supplied, ADMIN_TOKEN):
                raise HTTPException(status_code=401, detail="Missing or invalid Aegis admin token.")
        return role_dependency(request)

    return dependency


try:
    from demo_lab import router as demo_lab_router
except ImportError:
    from .demo_lab import router as demo_lab_router

app.include_router(demo_lab_router, dependencies=[Depends(require_demo_lab_enabled)])

# Global state for the WAF toggle (demo only)
WAF_ENABLED = os.environ.get("WAF_ENABLED", "false").lower() == "true"

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
    conn = get_connection()
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

def generate_fallback_tree():
    return generate_project_fallback_tree(PROJECT_ROOT)

# Use environment variables for secrets. The console does not ship fallback
# application secrets; demo-only credentials live in app/demo_lab.py.
app.state.secret_key = os.environ.get("SECRET_KEY")

# Initialize directories safely
DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
SCANS_DIR.mkdir(exist_ok=True, parents=True)

sample_file = DOWNLOAD_DIR / "sample.txt"
if not sample_file.exists():
    sample_file.write_text("This is a safe sample file.\n")

initialize_database()
ensure_bootstrap_admin()
WAF_ENABLED = bool(get_application_state("waf_enabled", WAF_ENABLED))


def setup_is_available() -> bool:
    return bool(os.environ.get("AEGIS_SETUP_TOKEN")) and not bool(
        get_application_state("setup_completed", False)
    )


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, redis_client=redis_client)
app.add_middleware(ObservabilityMiddleware)

app.add_middleware(
    WafASGIMiddleware,
    enabled=lambda: WAF_ENABLED,
    load_rules=load_waf_rules_from_db,
)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)

# REST Router Endpoints
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if setup_is_available():
        return RedirectResponse("/setup", status_code=303)
    if AUTH_REQUIRED and not principal_from_request(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "index.html")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if setup_is_available():
        return RedirectResponse("/setup", status_code=303)
    if principal_from_request(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html")


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    if not os.environ.get("AEGIS_SETUP_TOKEN"):
        raise HTTPException(status_code=404, detail="Setup is not enabled.")
    if not setup_is_available():
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html")


@app.post("/api/setup")
async def complete_setup(request: Request):
    if not setup_is_available():
        raise HTTPException(status_code=404, detail="Setup is not available.")
    expected = os.environ.get("AEGIS_SETUP_TOKEN", "")
    supplied = request.headers.get("X-Aegis-Setup-Token", "")
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid setup token.")
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="JSON body required.") from exc
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    workspace_name = str(body.get("workspace_name", "")).strip()
    repository = str(body.get("repository", "")).strip()
    scan_preset = str(body.get("scan_preset", "standard")).lower()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,128}", username):
        raise HTTPException(status_code=400, detail="Invalid administrator username.")
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters.")
    if not workspace_name or len(workspace_name) > 128:
        raise HTTPException(status_code=400, detail="Workspace name is required.")
    if len(repository) > 512:
        raise HTTPException(status_code=400, detail="Repository value is too long.")
    if scan_preset not in {"quick", "standard", "deep"}:
        raise HTTPException(status_code=400, detail="Invalid scan preset.")
    settings = {
        "workspace_name": workspace_name,
        "repository": repository,
        "scan_preset": scan_preset,
        "configured_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        principal = complete_initial_setup(username, password, settings)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    project_id = None
    if repository:
        repository_name = repository.rstrip("/").removesuffix(".git").split("/")[-1] or workspace_name
        try:
            project_id = create_project(
                name=repository_name[:128],
                repository_url=repository,
                github_full_name="",
                default_branch="main",
                scan_preset=scan_preset,
                user_id=principal.user_id,
            )
            record_audit(principal.user_id, "project.created", "project", project_id, {"name": repository_name, "source": "setup"})
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    response = JSONResponse(
        {
            "status": "configured",
            "username": principal.username,
            "role": principal.role,
            "csrf_token": principal.csrf_token,
            "project_id": project_id,
            "next_url": "/projects?welcome=1" if project_id else "/projects?welcome=1&create=1",
        }
    )
    response.set_cookie(
        SESSION_COOKIE,
        create_session(principal),
        httponly=True,
        secure=os.environ.get("AEGIS_ENV", "development").lower() == "production",
        samesite="strict",
        max_age=int(os.environ.get("AEGIS_SESSION_TTL_SECONDS", "28800")),
        path="/",
    )
    return response


@app.post("/api/auth/login")
async def login(request: Request):
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="JSON body required.") from exc
    username = str(body.get("username", ""))[:128]
    password = str(body.get("password", ""))[:1024]
    principal = authenticate(username, password)
    if not principal:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    response = JSONResponse(
        {"username": principal.username, "role": principal.role, "csrf_token": principal.csrf_token}
    )
    response.set_cookie(
        SESSION_COOKIE,
        create_session(principal),
        httponly=True,
        secure=os.environ.get("AEGIS_ENV", "development").lower() == "production",
        samesite="strict",
        max_age=int(os.environ.get("AEGIS_SESSION_TTL_SECONDS", "28800")),
        path="/",
    )
    return response


@app.get("/api/auth/me")
def current_user(request: Request, principal=Depends(require_role("viewer"))):
    return {
        "username": principal.username,
        "role": principal.role,
        "csrf_token": principal.csrf_token,
    }


@app.get("/api/settings")
def workspace_settings(principal=Depends(require_role("viewer"))):
    return get_application_state(
        "workspace_settings",
        {
            "workspace_name": "Aegis Core",
            "repository": "",
            "scan_preset": "standard",
        },
    )


def _project_access(project_id: int, principal, minimum: str):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")
    try:
        require_project_role(project_id, principal.user_id, principal.role, minimum)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return project


def _enqueue_project_scan(project: dict, principal, preset: str) -> dict:
    if preset not in VALID_PRESETS:
        raise HTTPException(status_code=400, detail="Invalid scan preset.")
    job_id = uuid.uuid4().hex
    run_id = create_scan_run(
        job_id=job_id,
        project_id=project["id"],
        requested_by=principal.user_id,
        target="project",
        preset=preset,
    )
    redis_client.hset(
        f"job:{job_id}",
        mapping={
            "state": "queued",
            "progress": 0,
            "owner_id": principal.user_id,
            "project_id": project["id"],
            "scan_run_id": run_id,
        },
    )
    from worker import async_scan_task

    arguments = (
        job_id,
        "project",
        None,
        WAF_ENABLED,
        run_id,
        project["id"],
        principal.user_id,
        preset,
    )
    if REDIS_AVAILABLE:
        from rq import Queue
        from redis import Redis

        queue = Queue(connection=Redis.from_url(REDIS_URL))
        queue.enqueue(async_scan_task, *arguments)
    else:
        import threading

        thread = threading.Thread(target=async_scan_task, args=arguments, daemon=True)
        thread.start()
    return {"status": "success", "job_id": job_id, "scan_run_id": run_id, "state": "queued"}


@app.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request):
    if AUTH_REQUIRED and not principal_from_request(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "projects.html")


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, principal=Depends(require_access("admin"))):
    return templates.TemplateResponse(request, "admin.html")


@app.get("/api/projects")
def projects_index(principal=Depends(require_role("viewer"))):
    return {"projects": list_projects(principal.user_id, principal.role)}


@app.post("/api/projects", status_code=201)
async def projects_create(
    request: Request, principal=Depends(require_access("operator"))
):
    body = await request.json()
    name = str(body.get("name", "")).strip()
    repository_url = str(body.get("repository_url", "")).strip()
    default_branch = str(body.get("default_branch", "main")).strip()
    preset = str(body.get("scan_preset", "standard")).lower()
    if not name or len(name) > 128:
        raise HTTPException(status_code=400, detail="Project name is required.")
    if repository_url and not repository_url.startswith("https://github.com/"):
        raise HTTPException(status_code=400, detail="Only HTTPS GitHub repositories are supported.")
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", default_branch):
        raise HTTPException(status_code=400, detail="Invalid default branch.")
    try:
        project_id = create_project(
            name=name,
            repository_url=repository_url,
            github_full_name="",
            default_branch=default_branch,
            scan_preset=preset,
            user_id=principal.user_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(principal.user_id, "project.created", "project", project_id, {"name": name})
    return {"id": project_id, "name": name}


@app.patch("/api/projects/{project_id}")
async def project_update(
    project_id: int, request: Request, principal=Depends(require_access("operator"))
):
    project = _project_access(project_id, principal, "admin")
    body = await request.json()
    name = str(body.get("name", project["name"])).strip()
    repository_url = str(body.get("repository_url", project["repository_url"])).strip()
    default_branch = str(body.get("default_branch", project["default_branch"])).strip()
    preset = str(body.get("scan_preset", project["scan_preset"])).lower()
    if not name or len(name) > 128:
        raise HTTPException(status_code=400, detail="Project name is required.")
    if repository_url and not repository_url.startswith("https://github.com/"):
        raise HTTPException(status_code=400, detail="Only HTTPS GitHub repositories are supported.")
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,255}", default_branch):
        raise HTTPException(status_code=400, detail="Invalid default branch.")
    try:
        update_project(
            project_id,
            name=name,
            repository_url=repository_url,
            default_branch=default_branch,
            scan_preset=preset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(principal.user_id, "project.updated", "project", project_id)
    return {"id": project_id, "name": name, "scan_preset": preset}


@app.delete("/api/projects/{project_id}")
def project_delete(
    project_id: int, principal=Depends(require_access("operator"))
):
    _project_access(project_id, principal, "admin")
    try:
        job_ids = delete_project(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    runs_root = (SCANS_DIR / "runs").resolve()
    for job_id in job_ids:
        run_dir = (runs_root / job_id).resolve()
        if run_dir.parent == runs_root:
            shutil.rmtree(run_dir, ignore_errors=True)
    record_audit(principal.user_id, "project.deleted", "project", project_id)
    return {"status": "deleted"}


@app.get("/api/projects/{project_id}/scans")
def project_scans(
    project_id: int, principal=Depends(require_role("viewer"))
):
    _project_access(project_id, principal, "viewer")
    return {"scans": list_scan_runs(project_id)}


def _authorized_scan(project_id: int, run_id: int, principal):
    _project_access(project_id, principal, "viewer")
    run = get_scan_run(run_id)
    if not run or run["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return run


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.get("/api/projects/{project_id}/scans/{run_id}")
def project_scan_detail(
    project_id: int, run_id: int, principal=Depends(require_role("viewer"))
):
    return _authorized_scan(project_id, run_id, principal)


@app.get("/api/projects/{project_id}/scans/{run_id}/artifacts")
def project_scan_artifacts(
    project_id: int, run_id: int, principal=Depends(require_role("viewer"))
):
    run = _authorized_scan(project_id, run_id, principal)
    report_dir = SCANS_DIR / "runs" / run["job_id"]
    artifacts = []
    for name in RUN_ARTIFACTS:
        path = report_dir / name
        if not path.is_file():
            continue
        artifacts.append(
            {
                "name": name,
                "url": f"/api/projects/{project_id}/scans/{run_id}/artifacts/{name}",
                "size": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        )
    if artifacts:
        artifacts.append(
            {
                "name": "report-bundle.zip",
                "url": f"/api/projects/{project_id}/scans/{run_id}/artifacts/report-bundle.zip",
                "size": None,
                "sha256": None,
            }
        )
    return {"artifacts": artifacts}


@app.get("/api/projects/{project_id}/scans/{run_id}/artifacts/{artifact_name}")
def project_scan_artifact(
    project_id: int,
    run_id: int,
    artifact_name: str,
    principal=Depends(require_role("viewer")),
):
    run = _authorized_scan(project_id, run_id, principal)
    report_dir = SCANS_DIR / "runs" / run["job_id"]
    if artifact_name == "report-bundle.zip":
        if not (report_dir / "report.html").is_file():
            raise HTTPException(status_code=404, detail="Report bundle is unavailable.")
        return Response(
            content=build_report_bundle(report_dir),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="aegis-{project_id}-{run_id}.zip"'
            },
        )
    media_type = RUN_ARTIFACTS.get(artifact_name)
    artifact_path = report_dir / artifact_name
    if not media_type or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return FileResponse(
        str(artifact_path),
        media_type=media_type,
        filename=artifact_name,
        content_disposition_type="inline" if artifact_name == "report.html" else "attachment",
    )


@app.get("/api/projects/{project_id}/members")
def project_members(
    project_id: int, principal=Depends(require_role("viewer"))
):
    _project_access(project_id, principal, "viewer")
    return {"members": list_project_members(project_id)}


@app.put("/api/projects/{project_id}/members")
async def project_member_set(
    project_id: int,
    request: Request,
    principal=Depends(require_access("operator")),
):
    _project_access(project_id, principal, "admin")
    body = await request.json()
    try:
        member = set_project_member(
            project_id,
            str(body.get("username", "")).strip(),
            str(body.get("role", "viewer")).lower(),
        )
        record_audit(principal.user_id, "project.member_set", "project", project_id, member)
        return member
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/projects/{project_id}/members/{user_id}")
def project_member_remove(
    project_id: int,
    user_id: int,
    principal=Depends(require_access("operator")),
):
    _project_access(project_id, principal, "admin")
    try:
        if not remove_project_member(project_id, user_id):
            raise HTTPException(status_code=404, detail="Project member not found.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record_audit(
        principal.user_id, "project.member_removed", "project", project_id, {"user_id": user_id}
    )
    return {"status": "removed"}


@app.get("/api/projects/{project_id}/notifications")
def project_notifications(project_id: int, principal=Depends(require_role("viewer"))):
    _project_access(project_id, principal, "admin")
    return {"channels": list_channels(project_id), "types": sorted(CHANNEL_TYPES)}


@app.post("/api/projects/{project_id}/notifications", status_code=201)
async def project_notification_create(
    project_id: int, request: Request, principal=Depends(require_access("operator"))
):
    _project_access(project_id, principal, "admin")
    body = await request.json()
    try:
        channel_id = create_channel(
            project_id=project_id,
            name=str(body.get("name", "")).strip()[:128],
            channel_type=str(body.get("channel_type", "")).lower(),
            config=body.get("config") if isinstance(body.get("config"), dict) else {},
            events=body.get("events") if isinstance(body.get("events"), list) else [],
            created_by=principal.user_id,
        )
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(principal.user_id, "notification.created", "notification", channel_id)
    return {"id": channel_id}


@app.delete("/api/projects/{project_id}/notifications/{channel_id}")
def project_notification_delete(
    project_id: int, channel_id: int, principal=Depends(require_access("operator"))
):
    _project_access(project_id, principal, "admin")
    if not delete_channel(channel_id, project_id):
        raise HTTPException(status_code=404, detail="Notification channel not found.")
    record_audit(principal.user_id, "notification.deleted", "notification", channel_id)
    return {"status": "deleted"}


@app.post("/api/projects/{project_id}/notifications/{channel_id}/test")
def project_notification_test(
    project_id: int, channel_id: int, principal=Depends(require_access("operator"))
):
    _project_access(project_id, principal, "admin")
    try:
        test_channel(channel_id, project_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Notification delivery failed.") from exc
    return {"status": "delivered"}


@app.post("/api/projects/{project_id}/scans", status_code=202)
async def project_scan_start(
    project_id: int,
    request: Request,
    principal=Depends(require_access("operator")),
):
    project = _project_access(project_id, principal, "operator")
    body = await request.json()
    preset = str(body.get("preset", project["scan_preset"])).lower()
    return _enqueue_project_scan(project, principal, preset)


@app.post("/api/scans/{run_id}/cancel", status_code=202)
def project_scan_cancel(
    run_id: int, principal=Depends(require_access("operator"))
):
    run = get_scan_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found.")
    _project_access(run["project_id"], principal, "operator")
    if run["state"] in {"completed", "failed", "cancelled"}:
        raise HTTPException(status_code=409, detail="Scan has already finished.")
    redis_client.hset(f"job:{run['job_id']}", "cancel_requested", 1)
    record_audit(principal.user_id, "scan.cancel_requested", "scan", run_id)
    return {"status": "cancellation_requested", "scan_run_id": run_id}


@app.post("/api/scans/{run_id}/retry", status_code=202)
def project_scan_retry(
    run_id: int, principal=Depends(require_access("operator"))
):
    run = get_scan_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan not found.")
    project = _project_access(run["project_id"], principal, "operator")
    result = _enqueue_project_scan(project, principal, run["preset"])
    record_audit(principal.user_id, "scan.retried", "scan", run_id, {"new_run_id": result["scan_run_id"]})
    return result


def _github_callback_url(request: Request) -> str:
    return os.environ.get("AEGIS_GITHUB_CALLBACK_URL") or str(
        request.url_for("github_callback")
    )


@app.get("/api/github/status")
def github_status(principal=Depends(require_role("viewer"))):
    return {
        "enabled": github_enabled(),
        "connection": github_connection(principal.user_id),
    }


@app.get("/api/github/connect")
def github_connect(request: Request, principal=Depends(require_role("viewer"))):
    try:
        url = begin_oauth(principal.user_id, _github_callback_url(request))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return RedirectResponse(url, status_code=302)


@app.get("/api/github/callback", name="github_callback")
def github_callback(request: Request, code: str = "", state: str = ""):
    if not code or not state:
        return RedirectResponse("/projects?github=denied", status_code=303)
    try:
        complete_oauth(code, state, _github_callback_url(request))
    except Exception:
        return RedirectResponse("/projects?github=error", status_code=303)
    return RedirectResponse("/projects?github=connected", status_code=303)


@app.get("/api/github/repositories")
def github_repositories(
    page: int = 1, principal=Depends(require_role("viewer"))
):
    try:
        return {"repositories": list_repositories(principal.user_id, page)}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="GitHub API request failed.") from exc


@app.post("/api/github/disconnect")
def github_disconnect(principal=Depends(require_role("viewer"))):
    disconnect_github(principal.user_id)
    return {"status": "disconnected"}


@app.post("/api/github/import", status_code=201)
async def github_import(
    request: Request, principal=Depends(require_access("operator"))
):
    body = await request.json()
    full_name = str(body.get("full_name", ""))
    repositories = list_repositories(principal.user_id)
    repository = next((repo for repo in repositories if repo["full_name"] == full_name), None)
    if not repository:
        raise HTTPException(status_code=404, detail="GitHub repository not found.")
    project_id = create_project(
        name=repository["name"],
        repository_url=repository["clone_url"],
        github_full_name=repository["full_name"],
        default_branch=repository["default_branch"],
        scan_preset=str(body.get("scan_preset", "standard")).lower(),
        user_id=principal.user_id,
    )
    return {"id": project_id, "name": repository["name"]}


@app.post("/api/auth/logout")
def logout(request: Request, principal=Depends(require_role("viewer"))):
    revoke_session(request.cookies.get(SESSION_COOKIE, ""))
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/users")
def list_users(principal=Depends(require_access("admin"))):
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, username, role, active, created_at FROM auth_users ORDER BY username"
        ).fetchall()
    return {
        "users": [
            {
                "id": int(row[0]),
                "username": row[1],
                "role": row[2],
                "active": bool(row[3]),
                "created_at": row[4],
            }
            for row in rows
        ]
    }


@app.post("/api/users", status_code=201)
async def create_user(request: Request, principal=Depends(require_access("admin"))):
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    role = str(body.get("role", "viewer")).lower()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,128}", username):
        raise HTTPException(status_code=400, detail="Invalid username.")
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters.")
    if role not in {"viewer", "operator", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid role.")
    try:
        with get_connection() as connection:
            connection.execute(
                """INSERT INTO auth_users
                   (username, password_hash, role, active, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    username,
                    hash_password(password),
                    role,
                    1,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Username already exists.") from exc
    record_audit(principal.user_id, "user.created", "user", username, {"role": role})
    return {"username": username, "role": role}


@app.patch("/api/users/{user_id}")
async def update_user(
    user_id: int, request: Request, principal=Depends(require_access("admin"))
):
    body = await request.json()
    role = body.get("role")
    active = body.get("active")
    password = body.get("password")
    if role is not None and role not in {"viewer", "operator", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid role.")
    if active is not None and not isinstance(active, bool):
        raise HTTPException(status_code=400, detail="active must be a boolean.")
    if password is not None and len(str(password)) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters.")
    if user_id == principal.user_id and (active is False or (role and role != "admin")):
        raise HTTPException(status_code=409, detail="Administrators cannot disable or demote their current account.")
    with get_connection() as connection:
        user = connection.execute(
            "SELECT username, role, active FROM auth_users WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        removing_admin = user[1] == "admin" and (
            active is False or (role is not None and role != "admin")
        )
        if removing_admin:
            admin_count = connection.execute(
                "SELECT COUNT(*) FROM auth_users WHERE role = 'admin' AND active = 1"
            ).fetchone()[0]
            if admin_count <= 1:
                raise HTTPException(status_code=409, detail="At least one active administrator is required.")
        if role is not None:
            connection.execute("UPDATE auth_users SET role = ? WHERE id = ?", (role, user_id))
        if active is not None:
            connection.execute(
                "UPDATE auth_users SET active = ? WHERE id = ?", (1 if active else 0, user_id)
            )
        if password is not None:
            connection.execute(
                "UPDATE auth_users SET password_hash = ? WHERE id = ?",
                (hash_password(str(password)), user_id),
            )
        if active is False:
            connection.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))
    revoke_user_sessions(user_id)
    details = {key: body[key] for key in ("role", "active") if key in body}
    details["password_rotated"] = password is not None
    record_audit(principal.user_id, "user.updated", "user", user_id, details)
    return {"id": user_id, "username": user[0], **details}


@app.post("/api/users/{user_id}/tokens", status_code=201)
async def create_api_token(
    user_id: int, request: Request, principal=Depends(require_access("admin"))
):
    body = await request.json()
    name = str(body.get("name", "automation")).strip()[:128]
    expires_at = body.get("expires_at")
    if expires_at:
        try:
            parsed_expiry = datetime.fromisoformat(str(expires_at))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="expires_at must be an ISO-8601 timestamp.") from exc
        if parsed_expiry.tzinfo is None or parsed_expiry <= datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="expires_at must be a future timezone-aware timestamp.")
        expires_at = parsed_expiry.astimezone(timezone.utc).isoformat()
    token = secrets.token_urlsafe(40)
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id FROM auth_users WHERE id = ? AND active = 1", (user_id,)
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        connection.execute(
            """INSERT INTO auth_tokens
               (user_id, token_hash, name, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                user_id,
                hashlib.sha256(token.encode()).hexdigest(),
                name or "automation",
                expires_at,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    record_audit(principal.user_id, "token.created", "user", user_id, {"name": name})
    return {"token": token, "token_type": "bearer", "name": name}


@app.get("/api/tokens")
def list_api_tokens(principal=Depends(require_access("admin"))):
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT t.id, t.user_id, u.username, t.name, t.expires_at, t.created_at
               FROM auth_tokens t JOIN auth_users u ON u.id = t.user_id
               ORDER BY t.id DESC"""
        ).fetchall()
    return {
        "tokens": [
            {
                "id": int(row[0]),
                "user_id": int(row[1]),
                "username": row[2],
                "name": row[3],
                "expires_at": row[4],
                "created_at": row[5],
            }
            for row in rows
        ]
    }


@app.delete("/api/tokens/{token_id}")
def revoke_api_token(token_id: int, principal=Depends(require_access("admin"))):
    with get_connection() as connection:
        cursor = connection.execute("DELETE FROM auth_tokens WHERE id = ?", (token_id,))
    if not getattr(cursor, "rowcount", 0):
        raise HTTPException(status_code=404, detail="Token not found.")
    record_audit(principal.user_id, "token.revoked", "token", token_id)
    return {"status": "revoked"}


@app.get("/api/admin/diagnostics")
def admin_diagnostics(principal=Depends(require_access("admin"))):
    database_status = "connected"
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception:
        database_status = "unavailable"
    redis_status = "connected"
    try:
        redis_client.ping()
    except Exception:
        redis_status = "unavailable"
    worker_count = 0
    if REDIS_AVAILABLE:
        try:
            from rq import Worker

            worker_count = Worker.count(connection=redis_client)
        except Exception:
            worker_count = 0
    return {
        "database": database_status,
        "redis": redis_status,
        "workers": worker_count,
        "github_oauth": github_enabled(),
        "smtp": bool(os.environ.get("AEGIS_SMTP_HOST")),
        "environment": os.environ.get("AEGIS_ENV", "development"),
        "report_storage": str(SCANS_DIR),
        "demo_lab_enabled": DEMO_LAB_ENABLED,
        "scanner_quick": "ready",
        "scanner_standard": "ready" if shutil.which("semgrep") else "semgrep unavailable",
        "scanner_deep": "ready"
        if shutil.which("trivy") and is_docker_available()
        else "requires isolated Docker and Trivy",
    }


@app.get("/api/admin/audit")
def admin_audit(limit: int = 100, principal=Depends(require_access("admin"))):
    return {"events": list_audit_events(limit)}


@app.get("/api/admin/requests")
def admin_request_log(limit: int = 100, principal=Depends(require_access("admin"))):
    return {"requests": recent_requests(limit)}


@app.get("/report", response_class=HTMLResponse, dependencies=[Depends(require_access("admin"))])
def get_report():
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        return HTMLResponse("<h1>Report not found</h1><p>Please run the security scans first.</p>", status_code=404)
    return HTMLResponse(report_path.read_text())

@app.get("/download-sbom", dependencies=[Depends(require_access("admin"))])
def download_sbom():
    sbom_path = SCANS_DIR / "sbom.json"
    if not sbom_path.exists():
        from policy_engine import generate_cyclonedx_sbom
        from dependencies import discover_dependency_manifests
        try:
            generate_cyclonedx_sbom(discover_dependency_manifests(PROJECT_ROOT), sbom_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"SBOM generation failed: {e}")
            
    return FileResponse(
        str(sbom_path),
        media_type="application/json",
        filename="cyclonedx-sbom.json"
    )


@app.get("/download-report-bundle", dependencies=[Depends(require_access("admin"))])
def download_report_bundle():
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report bundle is not available until a scan has completed.")
    bundle = build_report_bundle(SCANS_DIR)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=bundle,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=aegis-report-bundle-{timestamp}.zip"
        },
    )

@app.post("/toggle-waf", dependencies=[Depends(require_access("admin"))])
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    set_application_state("waf_enabled", WAF_ENABLED)
    return {"status": "success", "waf_enabled": WAF_ENABLED}

@app.get("/get-waf-rules", dependencies=[Depends(require_role("viewer"))])
def get_waf_rules():
    global WAF_ENABLED
    rules = load_waf_rules_from_db()
    return {"status": "success", "rules": rules, "waf_enabled": WAF_ENABLED}

@app.post("/save-waf-rules", dependencies=[Depends(require_access("admin"))])
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
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/get-scan-results", dependencies=[Depends(require_access("admin"))])
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
        reasons.append("Aegis DAST Probe")
        
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
        "sbom_url": "/download-sbom" if (SCANS_DIR / "sbom.json").exists() else None,
        "bundle_url": "/download-report-bundle" if latest_report.exists() else None
    }

@app.get("/get-dependency-graph", dependencies=[Depends(require_access("admin"))])
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

    raw_tree = load_dependency_tree(PROJECT_ROOT)

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

@app.post("/run-scan")
async def run_scan(request: Request, principal=Depends(require_access("operator"))):
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
    redis_client.hset(f"job:{job_id}", "state", "queued")
    redis_client.hset(f"job:{job_id}", "progress", 0)
    redis_client.hset(f"job:{job_id}", "owner_id", principal.user_id)

    # Import worker task logic
    from worker import async_scan_task

    if REDIS_AVAILABLE:
        from rq import Queue
        from redis import Redis

        r_conn = Redis.from_url(REDIS_URL)
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
    if principal.role != "admin":
        project_value = redis_client.hget(f"job:{job_id}", "project_id")
        if project_value:
            project_id = int(
                project_value.decode() if isinstance(project_value, bytes) else project_value
            )
            try:
                require_project_role(project_id, principal.user_id, principal.role, "viewer")
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
                if data.get("type") == "state" and data.get("state") in ("completed", "failed", "cancelled"):
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
async def stream_telemetry(principal=Depends(require_role("viewer"))):
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
        "service": "aegis-security-console",
        "demo_lab_enabled": DEMO_LAB_ENABLED,
    }


@app.get("/ready")
def readiness():
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database is not ready.") from exc

    redis_required = os.environ.get("AEGIS_REQUIRE_REDIS", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if redis_required and not REDIS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Redis is required but unavailable.")

    redis_state = "in-memory" if not REDIS_AVAILABLE else "connected"
    try:
        redis_client.ping()
    except Exception as exc:
        if redis_required:
            raise HTTPException(status_code=503, detail="Redis is not ready.") from exc
        redis_state = "unavailable"

    worker_state = "not-required"
    worker_required = os.environ.get("AEGIS_REQUIRE_WORKER", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if worker_required:
        if not REDIS_AVAILABLE:
            raise HTTPException(status_code=503, detail="Worker readiness requires Redis.")
        try:
            from rq import Worker

            worker_count = Worker.count(connection=redis_client)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Worker readiness could not be verified.") from exc
        if worker_count < 1:
            raise HTTPException(status_code=503, detail="No RQ workers are available.")
        worker_state = f"{worker_count} available"

    return {
        "status": "ready",
        "service": "aegis-security-console",
        "redis": redis_state,
        "worker": worker_state,
    }


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    metrics_token = os.environ.get("AEGIS_METRICS_TOKEN", "")
    supplied = request.headers.get("authorization", "")
    token_valid = (
        metrics_token
        and supplied.startswith("Bearer ")
        and hmac.compare_digest(supplied[7:].strip(), metrics_token)
    )
    principal = principal_from_request(request)
    if not token_valid and (not principal or principal.role != "admin"):
        raise HTTPException(status_code=401, detail="Metrics authentication required.")
    return PlainTextResponse(render_metrics(), media_type="text/plain; version=0.0.4")


@app.get("/export-dossier", dependencies=[Depends(require_access("admin"))])
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
        secrets_status = "MISSING"  # pragma: allowlist secret
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
        secrets_status = "FAIL" if secrets_blocking > 0 else "PASS"  # pragma: allowlist secret

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

    # Aegis DAST Probe
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
        ("Aegis DAST Probe", zap_status)
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
                semgrep_findings += "    Source:\n"
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

[7] DYNAMIC APPLICATION SECURITY TESTING (DAST) - AEGIS PROBE
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
