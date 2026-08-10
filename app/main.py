import os
import ipaddress
import re
import sys
import time
import random
import json
import logging
import asyncio
import hmac
import hashlib
import uuid
import secrets
import shutil
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, Request, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.datastructures import UploadFile
from werkzeug.utils import secure_filename

from .database import (
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
from .config import (
    environment_list,
    environment_positive_int,
    validate_runtime_configuration,
    validate_server_bind,
)
from .auth import (
    AUTH_REQUIRED,
    Principal,
    SESSION_COOKIE,
    TOKEN_SCOPES,
    authenticate,
    begin_mfa_setup,
    confirm_mfa_setup,
    complete_initial_setup,
    create_session,
    ensure_bootstrap_admin,
    ensure_development_admin,
    disable_mfa,
    hash_password,
    hash_api_token,
    principal_from_request,
    require_role,
    reauthenticate_session,
    revoke_session,
    revoke_user_sessions,
    session_authentication_is_recent,
    websocket_principal,
)
from .observability import (
    ObservabilityMiddleware,
    configure_logging,
    recent_requests,
    record_artifact_integrity_failure,
)
from .rate_limit import RateLimitMiddleware, allow_websocket
from .security_middleware import (
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
    WafASGIMiddleware,
)
from .projects import (
    VALID_PRESETS,
    create_project,
    create_scan_run,
    delete_project,
    get_project,
    get_scan_run,
    list_projects,
    list_project_members,
    list_scan_runs,
    get_scan_artifact,
    list_scan_artifacts,
    normalize_github_repository_url,
    remove_project_member,
    require_project_role,
    set_project_member,
    update_project,
)
from .github_integration import (
    begin_oauth,
    complete_oauth,
    disconnect_github,
    github_connection,
    github_app_enabled,
    github_enabled,
    list_repositories,
    github_webhook_enabled,
    create_check_run,
    create_repository_issue,
    mark_webhook_delivery,
    verify_and_record_webhook,
)
from .findings import get_finding, list_findings, update_finding
from .policies import (
    active_policy,
    approve_policy,
    create_policy,
    ensure_active_policy,
    list_policies,
    normalize_definition,
    simulate_policy,
)
from .oidc import begin_oidc, complete_oidc, oidc_enabled
from .notifications import CHANNEL_TYPES, create_channel, delete_channel, list_channels, queue_test_channel
from .audit import list_audit_events, record_audit, verify_audit_chain
from policy_engine import analyze_report_set, evaluate_policy_results, get_ruff_severity
from .sandbox import (
    get_active_sandbox_container,
    get_sandbox_logs,
    get_sandbox_stats,
    is_docker_available,
)
from .reporting import (
    build_report_bundle,
    build_report_bundle_from_artifacts,
    calculate_exploitability_score,
    generate_fallback_tree as generate_project_fallback_tree,
    load_json_report,
    load_dependency_tree,
)
from .artifact_storage import S3ArtifactStore, project_directory, run_directory
from .health_routes import router as health_router
from .scan_engine import ScanJobPayload
from .version import get_package_version

router = APIRouter()
logger = logging.getLogger("aegis.main")
DEMO_LAB_ENABLED = os.environ.get("AEGIS_ENABLE_DEMO_LAB", "false").lower() in {"1", "true", "yes", "on"}
ADMIN_TOKEN = os.environ.get("AEGIS_ADMIN_TOKEN")
MAX_UPLOAD_BYTES = environment_positive_int("AEGIS_MAX_UPLOAD_BYTES", 1024 * 1024)
MAX_REQUEST_BYTES = environment_positive_int(
    "AEGIS_MAX_REQUEST_BYTES", MAX_UPLOAD_BYTES + 64 * 1024
)
SCAN_JOB_TIMEOUT_SECONDS = environment_positive_int(
    "AEGIS_SCAN_JOB_TIMEOUT_SECONDS", 3600
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
    "iac-report.json": "application/json",
    "sandbox-status.json": "application/json",
    "scan-manifest.json": "application/json",
}

# Enable CORS for convenience.
def parse_cors_origins() -> list[str]:
    raw_origins = os.environ.get("AEGIS_CORS_ORIGINS", "http://127.0.0.1:5001,http://localhost:5001")
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


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


def _connection_is_loopback(connection: Request | WebSocket) -> bool:
    """Return whether the direct client for a local-only surface is loopback."""
    client = connection.client
    host = client.host.strip().lower() if client and client.host else ""
    # Starlette's TestClient uses a synthetic peer name. Treat it as local only
    # outside production; real production requests must carry an IP address.
    if host == "testclient":
        return os.environ.get("AEGIS_ENV", "development").lower() != "production"
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def require_demo_lab_access(
    request: Request,
    principal=Depends(require_access("admin")),
):
    require_demo_boundary(request)
    return principal


def require_demo_boundary(request: Request) -> None:
    """Keep every legacy threat-lab surface local and explicitly enabled."""

    require_demo_lab_enabled()
    if not _connection_is_loopback(request):
        raise HTTPException(
            status_code=403,
            detail="The Aegis demo lab is available only from a loopback client.",
        )


def require_recent_access(minimum_role: str):
    role_dependency = require_access(minimum_role)

    def dependency(request: Request):
        principal = role_dependency(request)
        if not AUTH_REQUIRED:
            return principal
        if principal.auth_method == "token":
            if "*" not in principal.scopes and "admin" not in principal.scopes:
                raise HTTPException(
                    status_code=403,
                    detail="This sensitive operation requires an admin-scoped API token.",
                )
            return principal
        session = request.cookies.get(SESSION_COOKIE, "")
        if not session_authentication_is_recent(session):
            raise HTTPException(
                status_code=403,
                detail="Recent authentication is required. Reauthenticate and try again.",
            )
        return principal

    return dependency


if DEMO_LAB_ENABLED:
    from .demo_lab import router as demo_lab_router

    router.include_router(
        demo_lab_router,
        prefix="/demo-lab",
        dependencies=[Depends(require_demo_lab_access)],
    )

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
    except Exception as exc:
        logger.warning("Unable to load WAF rules from the database: %s", exc)
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

# Public acquisition is intentionally separate from the authenticated workbench.
# This keeps the console's security boundary unchanged while giving prospective
# users a clear place to understand the product and request a pilot.
COMMERCIAL_CONTACT_URL = os.environ.get(
    "AEGIS_COMMERCIAL_CONTACT_URL",
    "https://github.com/huslenine999/aegis/issues/new",
)

def setup_is_available() -> bool:
    return bool(os.environ.get("AEGIS_SETUP_TOKEN")) and not bool(
        get_application_state("setup_completed", False)
    )


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Initialize mutable runtime state only when the ASGI app starts."""
    global WAF_ENABLED

    validate_runtime_configuration()
    configure_logging()
    DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
    SCANS_DIR.mkdir(exist_ok=True, parents=True)

    sample_file = DOWNLOAD_DIR / "sample.txt"
    if not sample_file.exists():
        sample_file.write_text("This is a safe sample file.\n")

    initialize_database()
    ensure_bootstrap_admin()
    ensure_development_admin()
    WAF_ENABLED = bool(get_application_state("waf_enabled", WAF_ENABLED))
    application.state.secret_key = os.environ.get("SECRET_KEY")
    yield


def create_app() -> FastAPI:
    """Build a fully configured Aegis ASGI application."""
    application = FastAPI(title="Aegis DevSecOps Console", lifespan=lifespan)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=parse_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    allowed_hosts = environment_list("AEGIS_ALLOWED_HOSTS")
    if allowed_hosts:
        application.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    application.mount(
        "/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static"
    )
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(RateLimitMiddleware, redis_client=redis_client)
    application.add_middleware(ObservabilityMiddleware)
    application.add_middleware(
        WafASGIMiddleware,
        enabled=lambda: WAF_ENABLED,
        load_rules=load_waf_rules_from_db,
    )
    application.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)
    application.include_router(router)
    application.include_router(health_router)
    return application

# REST Router Endpoints
@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    if setup_is_available():
        return RedirectResponse("/setup", status_code=303)
    if AUTH_REQUIRED and not principal_from_request(request):
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/projects", status_code=303)


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

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if setup_is_available():
        return RedirectResponse("/setup", status_code=303)
    if principal_from_request(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"oidc_enabled": oidc_enabled()}
    )


def _oidc_callback_url(request: Request) -> str:
    public_url = os.environ.get("AEGIS_PUBLIC_URL", "").rstrip("/")
    return f"{public_url}/api/auth/oidc/callback" if public_url else str(
        request.url_for("oidc_callback")
    )


@router.get("/api/auth/oidc/start")
def oidc_start(request: Request, return_to: str = "/"):
    try:
        authorization_url = begin_oidc(_oidc_callback_url(request), return_to)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return RedirectResponse(authorization_url, status_code=303)


@router.get("/api/auth/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, code: str = "", state: str = ""):
    if not code or not state:
        raise HTTPException(status_code=400, detail="OIDC callback is incomplete.")
    try:
        principal, return_to = await asyncio.to_thread(
            complete_oidc, code, state, _oidc_callback_url(request)
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="OIDC login failed.") from exc
    record_audit(principal.user_id, "auth.oidc_login_succeeded", "session")
    response = RedirectResponse(return_to, status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        await asyncio.to_thread(create_session, principal),
        httponly=True,
        secure=os.environ.get("AEGIS_ENV", "development").lower() == "production",
        samesite="strict",
        max_age=int(os.environ.get("AEGIS_SESSION_TTL_SECONDS", "28800")),
        path="/",
    )
    return response


@router.get("/account/security", response_class=HTMLResponse)
def account_security_page(request: Request):
    if AUTH_REQUIRED and not principal_from_request(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "account_security.html")


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    if not os.environ.get("AEGIS_SETUP_TOKEN"):
        raise HTTPException(status_code=404, detail="Setup is not enabled.")
    if not setup_is_available():
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html")


@router.post("/api/setup")
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
    try:
        repository = normalize_github_repository_url(repository)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if scan_preset not in {"quick", "standard", "deep"}:
        raise HTTPException(status_code=400, detail="Invalid scan preset.")
    settings = {
        "workspace_name": workspace_name,
        "repository": repository,
        "scan_preset": scan_preset,
        "configured_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        principal = await asyncio.to_thread(
            complete_initial_setup, username, password, settings
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    project_id = None
    if repository:
        repository_name = repository.rstrip("/").removesuffix(".git").split("/")[-1] or workspace_name
        try:
            project_id = await asyncio.to_thread(
                create_project,
                name=repository_name[:128],
                repository_url=repository,
                github_full_name="",
                default_branch="main",
                scan_preset=scan_preset,
                user_id=principal.user_id,
                tenant_id=principal.tenant_id,
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
        await asyncio.to_thread(create_session, principal),
        httponly=True,
        secure=os.environ.get("AEGIS_ENV", "development").lower() == "production",
        samesite="strict",
        max_age=int(os.environ.get("AEGIS_SESSION_TTL_SECONDS", "28800")),
        path="/",
    )
    return response


@router.post("/api/auth/login")
async def login(request: Request):
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="JSON body required.") from exc
    username = str(body.get("username", ""))[:128]
    password = str(body.get("password", ""))[:1024]
    second_factor = str(body.get("second_factor", ""))[:128]
    principal = await asyncio.to_thread(
        authenticate, username, password, second_factor
    )
    if not principal:
        record_audit(
            None,
            "auth.login_failed",
            "session",
            details={"username_sha256": hashlib.sha256(username.encode()).hexdigest()},
        )
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    record_audit(principal.user_id, "auth.login_succeeded", "session")
    response = JSONResponse(
        {
            "username": principal.username,
            "role": principal.role,
            "csrf_token": principal.csrf_token,
            "tenant_id": principal.tenant_id,
        }
    )
    response.set_cookie(
        SESSION_COOKIE,
        await asyncio.to_thread(create_session, principal),
        httponly=True,
        secure=os.environ.get("AEGIS_ENV", "development").lower() == "production",
        samesite="strict",
        max_age=int(os.environ.get("AEGIS_SESSION_TTL_SECONDS", "28800")),
        path="/",
    )
    return response


@router.get("/api/auth/me")
def current_user(request: Request, principal=Depends(require_role("viewer"))):
    with get_connection() as connection:
        mfa = connection.execute(
            "SELECT mfa_enabled FROM auth_users WHERE id = ? AND tenant_id = ?",
            (principal.user_id, principal.tenant_id),
        ).fetchone()
    return {
        "username": principal.username,
        "role": principal.role,
        "csrf_token": principal.csrf_token,
        "tenant_id": principal.tenant_id,
        "scopes": list(principal.scopes),
        "mfa_enabled": bool(mfa and mfa[0]),
    }


@router.post("/api/auth/reauth")
async def reauthenticate(
    request: Request, principal=Depends(require_role("viewer"))
):
    if principal.auth_method != "session":
        raise HTTPException(status_code=403, detail="Reauthentication requires a browser session.")
    body = await request.json()
    valid = await asyncio.to_thread(
        reauthenticate_session,
        request.cookies.get(SESSION_COOKIE, ""),
        principal,
        str(body.get("password", ""))[:1024],
        str(body.get("second_factor", ""))[:128],
    )
    if not valid:
        record_audit(principal.user_id, "auth.reauthentication_failed", "session")
        raise HTTPException(status_code=401, detail="Credential verification failed.")
    record_audit(principal.user_id, "auth.reauthenticated", "session")
    return {"status": "reauthenticated"}


@router.post("/api/auth/mfa/setup")
async def mfa_setup(
    request: Request, principal=Depends(require_recent_access("viewer"))
):
    if principal.auth_method != "session":
        raise HTTPException(status_code=403, detail="MFA setup requires a browser session.")
    body = await request.json()
    password = str(body.get("password", ""))[:1024]
    if not await asyncio.to_thread(authenticate, principal.username, password):
        raise HTTPException(status_code=403, detail="Current password is invalid.")
    try:
        setup = await asyncio.to_thread(
            begin_mfa_setup, principal.user_id, principal.username
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    record_audit(principal.user_id, "auth.mfa_setup_started", "user", principal.user_id)
    return setup


@router.post("/api/auth/mfa/confirm")
async def mfa_confirm(
    request: Request, principal=Depends(require_recent_access("viewer"))
):
    if principal.auth_method != "session":
        raise HTTPException(status_code=403, detail="MFA setup requires a browser session.")
    body = await request.json()
    try:
        recovery_codes = await asyncio.to_thread(
            confirm_mfa_setup, principal.user_id, str(body.get("code", ""))
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(principal.user_id, "auth.mfa_enabled", "user", principal.user_id)
    revoke_user_sessions(principal.user_id)
    response = JSONResponse(
        {
            "status": "enabled",
            "recovery_codes": recovery_codes,
            "message": "Store these recovery codes now; they will not be shown again.",
        }
    )
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.delete("/api/auth/mfa")
async def mfa_disable(
    request: Request, principal=Depends(require_recent_access("viewer"))
):
    if principal.auth_method != "session":
        raise HTTPException(status_code=403, detail="MFA changes require a browser session.")
    body = await request.json()
    disabled = await asyncio.to_thread(
        disable_mfa,
        principal.user_id,
        str(body.get("password", "")),
        str(body.get("code", "")),
    )
    if not disabled:
        raise HTTPException(status_code=403, detail="Password or second factor is invalid.")
    record_audit(principal.user_id, "auth.mfa_disabled", "user", principal.user_id)
    revoke_user_sessions(principal.user_id)
    response = JSONResponse({"status": "disabled"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/api/settings")
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
    project = get_project(project_id, principal.tenant_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")
    try:
        require_project_role(
            project_id,
            principal.user_id,
            principal.role,
            minimum,
            principal.tenant_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return project


def _enqueue_project_scan(
    project: dict, principal, preset: str, github_context: dict | None = None
) -> dict:
    if preset not in VALID_PRESETS:
        raise HTTPException(status_code=400, detail="Invalid scan preset.")
    try:
        policy = ensure_active_policy(project["id"], principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job_id = uuid.uuid4().hex
    run_id = create_scan_run(
        job_id=job_id,
        project_id=project["id"],
        requested_by=principal.user_id,
        target="project",
        preset=preset,
        source_revision=(github_context or {}).get("head_sha"),
        source_ref=(github_context or {}).get("head_ref"),
        github_installation_id=(github_context or {}).get("installation_id"),
        github_pull_request=(github_context or {}).get("pull_request"),
        github_check_run_id=(github_context or {}).get("check_run_id"),
        policy_version_id=policy["id"],
    )
    redis_client.hset(
        f"job:{job_id}",
        mapping={
            "state": "queued",
            "progress": 0,
            "owner_id": principal.user_id,
            "project_id": project["id"],
            "scan_run_id": run_id,
            "queued_at": time.time(),
        },
    )
    from .worker import async_scan_task

    payload = ScanJobPayload(
        job_id=job_id,
        target="project",
        waf_enabled=WAF_ENABLED,
        scan_run_id=run_id,
        project_id=project["id"],
        requested_by=principal.user_id,
        preset=preset,
        source_revision=(github_context or {}).get("head_sha"),
        github_installation_id=(github_context or {}).get("installation_id"),
    )
    if REDIS_AVAILABLE:
        from rq import Queue
        from redis import Redis

        queue = Queue(
            "deep" if preset == "deep" else "default",
            connection=Redis.from_url(REDIS_URL),
        )
        queue.enqueue(async_scan_task, payload, job_timeout=SCAN_JOB_TIMEOUT_SECONDS)
    else:
        import threading

        thread = threading.Thread(target=async_scan_task, args=(payload,), daemon=True)
        thread.start()
    return {
        "status": "success",
        "job_id": job_id,
        "scan_run_id": run_id,
        "state": "queued",
        "policy_version": policy["version"],
    }


@router.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request):
    if AUTH_REQUIRED and not principal_from_request(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "projects.html",
        {"demo_lab_enabled": DEMO_LAB_ENABLED},
    )


@router.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, principal=Depends(require_access("admin"))):
    return templates.TemplateResponse(request, "admin.html")


@router.get("/api/projects")
def projects_index(principal=Depends(require_role("viewer"))):
    return {
        "projects": list_projects(
            principal.user_id, principal.role, principal.tenant_id
        )
    }


@router.post("/api/projects", status_code=201)
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
    try:
        repository_url = normalize_github_repository_url(repository_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
            tenant_id=principal.tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(principal.user_id, "project.created", "project", project_id, {"name": name})
    return {"id": project_id, "name": name}


@router.patch("/api/projects/{project_id}")
async def project_update(
    project_id: int, request: Request, principal=Depends(require_recent_access("operator"))
):
    project = _project_access(project_id, principal, "admin")
    body = await request.json()
    name = str(body.get("name", project["name"])).strip()
    repository_url = str(body.get("repository_url", project["repository_url"])).strip()
    default_branch = str(body.get("default_branch", project["default_branch"])).strip()
    preset = str(body.get("scan_preset", project["scan_preset"])).lower()
    if not name or len(name) > 128:
        raise HTTPException(status_code=400, detail="Project name is required.")
    try:
        repository_url = normalize_github_repository_url(repository_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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


@router.delete("/api/projects/{project_id}")
def project_delete(
    project_id: int, principal=Depends(require_recent_access("operator"))
):
    project = _project_access(project_id, principal, "admin")
    try:
        job_ids = delete_project(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    runs_root = (SCANS_DIR / "runs").resolve()
    for job_id in job_ids:
        run_dir = (runs_root / job_id).resolve()
        if run_dir.parent == runs_root:
            shutil.rmtree(run_dir, ignore_errors=True)
    scoped_project_dir = project_directory(
        SCANS_DIR, project["tenant_id"], project_id
    )
    shutil.rmtree(scoped_project_dir, ignore_errors=True)
    record_audit(principal.user_id, "project.deleted", "project", project_id)
    return {"status": "deleted"}


@router.get("/api/projects/{project_id}/scans")
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


def _artifact_integrity(metadata: dict, path: Path) -> bool:
    if metadata.get("backend") == "s3":
        key = metadata.get("storage_key")
        return bool(
            key
            and S3ArtifactStore().verify(key, metadata["size"], metadata["sha256"])
        )
    return (
        path.is_file()
        and path.stat().st_size == metadata["size"]
        and _file_sha256(path) == metadata["sha256"]
    )


def _artifact_bytes(metadata: dict, path: Path) -> bytes:
    if not _artifact_integrity(metadata, path):
        record_artifact_integrity_failure()
        raise HTTPException(status_code=409, detail="Artifact integrity verification failed.")
    if metadata.get("backend") == "s3":
        content = S3ArtifactStore().read(metadata["storage_key"])
        if len(content) != metadata["size"] or hashlib.sha256(content).hexdigest() != metadata["sha256"]:
            record_artifact_integrity_failure()
            raise HTTPException(status_code=409, detail="Artifact integrity verification failed.")
        return content
    return path.read_bytes()


@router.get("/api/projects/{project_id}/scans/{run_id}")
def project_scan_detail(
    project_id: int, run_id: int, principal=Depends(require_role("viewer"))
):
    return _authorized_scan(project_id, run_id, principal)


@router.get("/api/projects/{project_id}/scans/{run_id}/artifacts")
def project_scan_artifacts(
    project_id: int, run_id: int, principal=Depends(require_role("viewer"))
):
    run = _authorized_scan(project_id, run_id, principal)
    report_dir = run_directory(
        SCANS_DIR,
        run["job_id"],
        tenant_id=run.get("tenant_id"),
        project_id=project_id,
    )
    artifacts = []
    for metadata in list_scan_artifacts(run_id):
        name = metadata["name"]
        path = report_dir / name
        if name not in RUN_ARTIFACTS:
            continue
        try:
            integrity = _artifact_integrity(metadata, path)
        except Exception as exc:
            logger.warning(
                "Artifact integrity verification failed for run %s artifact %s: %s",
                run_id,
                name,
                exc,
            )
            integrity = False
        if not integrity:
            record_artifact_integrity_failure()
        artifacts.append(
            {
                **metadata,
                "url": f"/api/projects/{project_id}/scans/{run_id}/artifacts/{name}",
                "integrity": "verified" if integrity else "failed",
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


@router.get("/api/projects/{project_id}/scans/{run_id}/artifacts/{artifact_name}")
def project_scan_artifact(
    project_id: int,
    run_id: int,
    artifact_name: str,
    principal=Depends(require_role("viewer")),
):
    run = _authorized_scan(project_id, run_id, principal)
    report_dir = run_directory(
        SCANS_DIR,
        run["job_id"],
        tenant_id=run.get("tenant_id"),
        project_id=project_id,
    )
    if artifact_name == "report-bundle.zip":
        recorded = list_scan_artifacts(run_id)
        if not recorded or not any(item["name"] == "report.html" for item in recorded):
            raise HTTPException(status_code=404, detail="Report bundle is unavailable.")
        stored_artifacts = {}
        for metadata in recorded:
            path = report_dir / metadata["name"]
            stored_artifacts[metadata["name"]] = _artifact_bytes(metadata, path)
        return Response(
            content=build_report_bundle_from_artifacts(stored_artifacts),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="aegis-{project_id}-{run_id}.zip"'
            },
        )
    media_type = RUN_ARTIFACTS.get(artifact_name)
    artifact_path = report_dir / artifact_name
    artifact_metadata = get_scan_artifact(run_id, artifact_name)
    if not media_type or not artifact_metadata:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    if artifact_metadata.get("backend") == "s3":
        return Response(
            content=_artifact_bytes(artifact_metadata, artifact_path),
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{artifact_name}"'},
        )
    if not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found.")
    _artifact_bytes(artifact_metadata, artifact_path)
    return FileResponse(
        str(artifact_path),
        media_type=media_type,
        filename=artifact_name,
        content_disposition_type="attachment",
    )


@router.get("/api/projects/{project_id}/findings")
def project_findings(
    project_id: int,
    status: str | None = None,
    severity: str | None = None,
    principal=Depends(require_role("viewer")),
):
    _project_access(project_id, principal, "viewer")
    try:
        findings = list_findings(project_id, status=status, severity=severity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"findings": findings}


@router.get("/api/projects/{project_id}/findings/{finding_id}")
def project_finding_detail(
    project_id: int,
    finding_id: int,
    principal=Depends(require_role("viewer")),
):
    _project_access(project_id, principal, "viewer")
    finding = get_finding(project_id, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding


@router.patch("/api/projects/{project_id}/findings/{finding_id}")
async def project_finding_update(
    project_id: int,
    finding_id: int,
    request: Request,
    principal=Depends(require_recent_access("operator")),
):
    _project_access(project_id, principal, "operator")
    body = await request.json()
    try:
        finding = update_finding(project_id, finding_id, principal.user_id, body)
    except ValueError as exc:
        status_code = 404 if str(exc) == "Finding not found." else 400
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    record_audit(
        principal.user_id,
        "finding.updated",
        "finding",
        finding_id,
        {"project_id": project_id, "status": finding["status"]},
    )
    return finding


@router.post("/api/projects/{project_id}/findings/{finding_id}/github-issue", status_code=201)
async def project_finding_github_issue(
    project_id: int,
    finding_id: int,
    request: Request,
    principal=Depends(require_recent_access("operator")),
):
    project = _project_access(project_id, principal, "operator")
    finding = get_finding(project_id, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if finding.get("ticket_url"):
        raise HTTPException(status_code=409, detail="Finding already has a remediation ticket.")
    repository = project.get("github_full_name")
    if not repository:
        raise HTTPException(status_code=400, detail="Project is not linked to a GitHub repository.")
    body = await request.json()
    title = str(body.get("title") or f"[{finding['severity']}] {finding['title']}")
    issue_body = str(body.get("body") or "\n".join([
        "## Aegis security finding",
        "",
        f"- Tool: {finding['tool']}",
        f"- Rule: {finding['rule_id'] or 'n/a'}",
        f"- Severity: {finding['severity']}",
        f"- Location: {finding['path'] or 'n/a'}:{finding['line_number'] or '-'}",
        f"- First seen scan: {finding['first_seen_run_id']}",
        f"- Latest scan: {finding['last_seen_run_id']}",
        "",
        "Resolve the underlying issue, then run Aegis again to verify remediation.",
    ]))
    try:
        issue = await asyncio.to_thread(
            create_repository_issue,
            principal.user_id,
            repository,
            title=title,
            body=issue_body,
        )
        finding = update_finding(
            project_id,
            finding_id,
            principal.user_id,
            {"ticket_url": issue["url"]},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="GitHub issue creation failed.") from exc
    record_audit(
        principal.user_id,
        "finding.github_issue_created",
        "finding",
        finding_id,
        {"project_id": project_id, "issue": issue["number"]},
    )
    return {"issue": issue, "finding": finding}


@router.get("/api/projects/{project_id}/policies")
def project_policies(
    project_id: int, principal=Depends(require_role("viewer"))
):
    _project_access(project_id, principal, "viewer")
    return {"policies": list_policies(project_id), "active": active_policy(project_id)}


@router.post("/api/projects/{project_id}/policies", status_code=201)
async def project_policy_create(
    project_id: int,
    request: Request,
    principal=Depends(require_recent_access("operator")),
):
    _project_access(project_id, principal, "admin")
    body = await request.json()
    try:
        policy = create_policy(
            project_id,
            principal.user_id,
            str(body.get("name") or ""),
            body.get("definition") or {},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(
        principal.user_id, "policy.created", "policy", policy["id"],
        {"project_id": project_id, "version": policy["version"]},
    )
    return policy


@router.post("/api/projects/{project_id}/policies/{policy_id}/approve")
def project_policy_approve(
    project_id: int,
    policy_id: int,
    principal=Depends(require_recent_access("operator")),
):
    _project_access(project_id, principal, "admin")
    try:
        policy = approve_policy(project_id, policy_id, principal.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(
        principal.user_id, "policy.approved", "policy", policy_id,
        {"project_id": project_id, "version": policy["version"]},
    )
    return policy


@router.post("/api/projects/{project_id}/policies/simulate")
async def project_policy_simulate(
    project_id: int,
    request: Request,
    principal=Depends(require_role("viewer")),
):
    _project_access(project_id, principal, "viewer")
    body = await request.json()
    try:
        definition = normalize_definition(body.get("definition") or {})
        return simulate_policy(project_id, int(body.get("scan_run_id")), definition)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/projects/{project_id}/members")
def project_members(
    project_id: int, principal=Depends(require_role("viewer"))
):
    _project_access(project_id, principal, "viewer")
    return {"members": list_project_members(project_id)}


@router.put("/api/projects/{project_id}/members")
async def project_member_set(
    project_id: int,
    request: Request,
    principal=Depends(require_recent_access("operator")),
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


@router.delete("/api/projects/{project_id}/members/{user_id}")
def project_member_remove(
    project_id: int,
    user_id: int,
    principal=Depends(require_recent_access("operator")),
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


@router.get("/api/projects/{project_id}/notifications")
def project_notifications(project_id: int, principal=Depends(require_role("viewer"))):
    _project_access(project_id, principal, "admin")
    return {"channels": list_channels(project_id), "types": sorted(CHANNEL_TYPES)}


@router.post("/api/projects/{project_id}/notifications", status_code=201)
async def project_notification_create(
    project_id: int, request: Request, principal=Depends(require_recent_access("operator"))
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


@router.delete("/api/projects/{project_id}/notifications/{channel_id}")
def project_notification_delete(
    project_id: int, channel_id: int, principal=Depends(require_recent_access("operator"))
):
    _project_access(project_id, principal, "admin")
    if not delete_channel(channel_id, project_id):
        raise HTTPException(status_code=404, detail="Notification channel not found.")
    record_audit(principal.user_id, "notification.deleted", "notification", channel_id)
    return {"status": "deleted"}


@router.post("/api/projects/{project_id}/notifications/{channel_id}/test")
def project_notification_test(
    project_id: int, channel_id: int, principal=Depends(require_recent_access("operator"))
):
    _project_access(project_id, principal, "admin")
    try:
        if not queue_test_channel(channel_id, project_id):
            raise RuntimeError("Notifier queue is unavailable.")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Notification delivery failed.") from exc
    return {"status": "queued"}


@router.post("/api/projects/{project_id}/scans", status_code=202)
async def project_scan_start(
    project_id: int,
    request: Request,
    principal=Depends(require_access("operator")),
):
    project = _project_access(project_id, principal, "operator")
    body = await request.json()
    preset = str(body.get("preset", project["scan_preset"])).lower()
    return _enqueue_project_scan(project, principal, preset)


@router.post("/api/scans/{run_id}/cancel", status_code=202)
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


@router.post("/api/scans/{run_id}/retry", status_code=202)
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


@router.post("/api/github/webhook", status_code=202)
async def github_webhook(request: Request):
    """Authenticate, deduplicate, and record GitHub App webhook deliveries."""
    if not github_webhook_enabled():
        raise HTTPException(status_code=404, detail="GitHub webhooks are not enabled.")
    body = await request.body()
    try:
        delivery = verify_and_record_webhook(
            body,
            signature_header=request.headers.get("X-Hub-Signature-256", ""),
            delivery_id=request.headers.get("X-GitHub-Delivery", ""),
            event_type=request.headers.get("X-GitHub-Event", ""),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        status_code = 409 if "already been processed" in str(exc) else 401
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    tenant_id = 1
    project = None
    project_owner = None
    if delivery["repository"]:
        with get_connection() as connection:
            row = connection.execute(
                """SELECT p.id, p.tenant_id, p.created_by, u.username, u.role
                   FROM projects p JOIN auth_users u ON u.id = p.created_by
                   WHERE p.github_full_name = ? AND u.active = 1 ORDER BY p.id LIMIT 1""",
                (delivery["repository"],),
            ).fetchone()
            if row:
                tenant_id = int(row[1])
                project = get_project(int(row[0]), tenant_id)
                project_owner = Principal(
                    int(row[2]), row[3], row[4], "", tenant_id
                )
    record_audit(
        None,
        "github.webhook.accepted",
        "github_delivery",
        delivery["delivery_id"],
        {
            "event_type": delivery["event_type"],
            "repository": delivery["repository"],
            "payload_sha256": delivery["payload_sha256"],
        },
        tenant_id=tenant_id,
    )
    automation = None
    try:
        should_scan = (
            delivery["event_type"] == "pull_request"
            and delivery["action"] in {"opened", "reopened", "synchronize"}
        )
        if not should_scan or not project or not project_owner:
            mark_webhook_delivery(delivery["delivery_id"], "ignored")
        else:
            if not github_app_enabled():
                raise RuntimeError(
                    "Pull-request automation requires a configured GitHub App private key."
                )
            installation_id = int(delivery["installation_id"])
            pull_request = int(delivery["pull_request"])
            head_sha = delivery["head_sha"]
            if (
                installation_id < 1
                or pull_request < 1
                or not re.fullmatch(r"[0-9a-f]{40,64}", head_sha)
            ):
                raise ValueError("GitHub pull-request context is invalid.")
            details_base = os.environ.get("AEGIS_PUBLIC_URL", "").rstrip("/")
            details_url = (
                f"{details_base}/projects" if details_base.startswith("https://") else ""
            )
            check_run_id = await asyncio.to_thread(
                create_check_run,
                installation_id,
                delivery["repository"],
                head_sha,
                details_url,
            )
            automation = _enqueue_project_scan(
                project,
                project_owner,
                project["scan_preset"],
                {
                    "installation_id": installation_id,
                    "pull_request": pull_request,
                    "head_sha": head_sha,
                    "head_ref": delivery["head_ref"],
                    "check_run_id": check_run_id,
                },
            )
            mark_webhook_delivery(
                delivery["delivery_id"], "processed", automation["scan_run_id"]
            )
            record_audit(
                project_owner.user_id,
                "github.pull_request_scan_queued",
                "project",
                project["id"],
                {
                    "pull_request": pull_request,
                    "revision": head_sha,
                    "scan_run_id": automation["scan_run_id"],
                },
                tenant_id=tenant_id,
            )
    except Exception as exc:
        mark_webhook_delivery(delivery["delivery_id"], "failed")
        record_audit(
            None,
            "github.webhook_processing_failed",
            "github_delivery",
            delivery["delivery_id"],
            {"error_type": type(exc).__name__},
            tenant_id=tenant_id,
        )
        raise HTTPException(status_code=502, detail="GitHub webhook processing failed.") from exc
    return {
        "status": "accepted",
        "delivery_id": delivery["delivery_id"],
        "event_type": delivery["event_type"],
        "automation": automation,
    }


@router.get("/api/github/status")
def github_status(principal=Depends(require_role("viewer"))):
    return {
        "enabled": github_enabled(),
        "connection": github_connection(principal.user_id),
    }


@router.get("/api/github/connect")
def github_connect(request: Request, principal=Depends(require_recent_access("viewer"))):
    try:
        url = begin_oauth(principal.user_id, _github_callback_url(request))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return RedirectResponse(url, status_code=302)


@router.get("/api/github/callback", name="github_callback")
def github_callback(request: Request, code: str = "", state: str = ""):
    if not code or not state:
        return RedirectResponse("/projects?github=denied", status_code=303)
    try:
        complete_oauth(code, state, _github_callback_url(request))
    except Exception as exc:
        logger.warning("GitHub OAuth callback failed: %s", exc)
        return RedirectResponse("/projects?github=error", status_code=303)
    return RedirectResponse("/projects?github=connected", status_code=303)


@router.get("/api/github/repositories")
def github_repositories(
    page: int = 1, principal=Depends(require_role("viewer"))
):
    try:
        return {"repositories": list_repositories(principal.user_id, page)}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="GitHub API request failed.") from exc


@router.post("/api/github/disconnect")
def github_disconnect(principal=Depends(require_recent_access("viewer"))):
    disconnect_github(principal.user_id)
    return {"status": "disconnected"}


@router.post("/api/github/import", status_code=201)
async def github_import(
    request: Request, principal=Depends(require_access("operator"))
):
    body = await request.json()
    full_name = str(body.get("full_name", ""))
    repositories = await asyncio.to_thread(list_repositories, principal.user_id)
    repository = next((repo for repo in repositories if repo["full_name"] == full_name), None)
    if not repository:
        raise HTTPException(status_code=404, detail="GitHub repository not found.")
    project_id = await asyncio.to_thread(
        create_project,
        name=repository["name"],
        repository_url=repository["clone_url"],
        github_full_name=repository["full_name"],
        default_branch=repository["default_branch"],
        scan_preset=str(body.get("scan_preset", "standard")).lower(),
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
    )
    return {"id": project_id, "name": repository["name"]}


@router.post("/api/auth/logout")
def logout(request: Request, principal=Depends(require_role("viewer"))):
    record_audit(principal.user_id, "auth.logout", "session")
    revoke_session(request.cookies.get(SESSION_COOKIE, ""))
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.get("/api/users")
def list_users(principal=Depends(require_access("admin"))):
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT id, username, role, active, created_at FROM auth_users
               WHERE tenant_id = ? ORDER BY username""",
            (principal.tenant_id,),
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


@router.post("/api/users", status_code=201)
async def create_user(request: Request, principal=Depends(require_recent_access("admin"))):
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
                   (username, password_hash, role, active, created_at, tenant_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    username,
                    hash_password(password),
                    role,
                    1,
                    datetime.now(timezone.utc).isoformat(),
                    principal.tenant_id,
                ),
            )
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Username already exists.") from exc
    record_audit(principal.user_id, "user.created", "user", username, {"role": role})
    return {"username": username, "role": role}


@router.patch("/api/users/{user_id}")
async def update_user(
    user_id: int, request: Request, principal=Depends(require_recent_access("admin"))
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
            """SELECT username, role, active FROM auth_users
               WHERE id = ? AND tenant_id = ?""",
            (user_id, principal.tenant_id),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        removing_admin = user[1] == "admin" and (
            active is False or (role is not None and role != "admin")
        )
        if removing_admin:
            admin_count = connection.execute(
                """SELECT COUNT(*) FROM auth_users
                   WHERE role = 'admin' AND active = 1 AND tenant_id = ?""",
                (principal.tenant_id,),
            ).fetchone()[0]
            if admin_count <= 1:
                raise HTTPException(status_code=409, detail="At least one active administrator is required.")
        if role is not None:
            connection.execute(
                "UPDATE auth_users SET role = ? WHERE id = ? AND tenant_id = ?",
                (role, user_id, principal.tenant_id),
            )
        if active is not None:
            connection.execute(
                """UPDATE auth_users SET active = ?
                   WHERE id = ? AND tenant_id = ?""",
                (1 if active else 0, user_id, principal.tenant_id),
            )
        if password is not None:
            connection.execute(
                """UPDATE auth_users SET password_hash = ?, failed_login_count = 0,
                   locked_until = NULL WHERE id = ? AND tenant_id = ?""",
                (hash_password(str(password)), user_id, principal.tenant_id),
            )
        if active is False:
            connection.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))
    revoke_user_sessions(user_id)
    details = {key: body[key] for key in ("role", "active") if key in body}
    details["password_rotated"] = password is not None
    record_audit(principal.user_id, "user.updated", "user", user_id, details)
    return {"id": user_id, "username": user[0], **details}


@router.post("/api/users/{user_id}/tokens", status_code=201)
async def create_api_token(
    user_id: int, request: Request, principal=Depends(require_recent_access("admin"))
):
    body = await request.json()
    name = str(body.get("name", "automation")).strip()[:128]
    expires_at = body.get("expires_at")
    requested_scopes = body.get("scopes")
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
            """SELECT id, role FROM auth_users
               WHERE id = ? AND active = 1 AND tenant_id = ?""",
            (user_id, principal.tenant_id),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        default_scopes = {
            "viewer": ["read"],
            "operator": ["read", "write"],
            "admin": ["read", "write", "admin"],
        }[user[1]]
        scopes = requested_scopes if requested_scopes is not None else default_scopes
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(str(scope) not in TOKEN_SCOPES for scope in scopes)
        ):
            raise HTTPException(
                status_code=400,
                detail="scopes must be a non-empty list containing read, write, or admin.",
            )
        scopes = sorted({str(scope) for scope in scopes})
        allowed_by_role = set(default_scopes)
        if not set(scopes).issubset(allowed_by_role):
            raise HTTPException(status_code=400, detail="Token scope exceeds the user's role.")
        connection.execute(
            """INSERT INTO auth_tokens
               (user_id, token_hash, name, expires_at, created_at, scopes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                hash_api_token(token),
                name or "automation",
                expires_at,
                datetime.now(timezone.utc).isoformat(),
                ",".join(scopes),
            ),
        )
    record_audit(
        principal.user_id,
        "token.created",
        "user",
        user_id,
        {"name": name, "scopes": scopes, "expires_at": expires_at},
    )
    return {
        "token": token,  # pragma: allowlist secret
        "token_type": "bearer",  # pragma: allowlist secret
        "name": name,
        "scopes": scopes,
        "expires_at": expires_at,
    }


@router.get("/api/tokens")
def list_api_tokens(principal=Depends(require_access("admin"))):
    with get_connection() as connection:
        rows = connection.execute(
            """SELECT t.id, t.user_id, u.username, t.name, t.expires_at,
                      t.created_at, t.scopes, t.last_used_at
               FROM auth_tokens t JOIN auth_users u ON u.id = t.user_id
               WHERE u.tenant_id = ?
               ORDER BY t.id DESC"""
            , (principal.tenant_id,)
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
                "scopes": row[6].split(",") if row[6] else ["read"],
                "last_used_at": row[7],
            }
            for row in rows
        ]
    }


@router.delete("/api/tokens/{token_id}")
def revoke_api_token(token_id: int, principal=Depends(require_recent_access("admin"))):
    with get_connection() as connection:
        cursor = connection.execute(
            """DELETE FROM auth_tokens WHERE id = ? AND user_id IN
               (SELECT id FROM auth_users WHERE tenant_id = ?)""",
            (token_id, principal.tenant_id),
        )
    if not getattr(cursor, "rowcount", 0):
        raise HTTPException(status_code=404, detail="Token not found.")
    record_audit(principal.user_id, "token.revoked", "token", token_id)
    return {"status": "revoked"}


@router.get("/api/admin/diagnostics")
def admin_diagnostics(principal=Depends(require_access("admin"))):
    database_status = "connected"
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception as exc:
        logger.warning("Database diagnostics failed: %s", exc)
        database_status = "unavailable"
    redis_status = "connected"
    try:
        redis_client.ping()
    except Exception as exc:
        logger.warning("Redis diagnostics failed: %s", exc)
        redis_status = "unavailable"
    worker_count = 0
    if REDIS_AVAILABLE:
        try:
            from rq import Worker

            worker_count = Worker.count(connection=redis_client)
        except Exception as exc:
            logger.warning("Worker diagnostics failed: %s", exc)
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


@router.get("/api/admin/audit")
def admin_audit(limit: int = 100, principal=Depends(require_access("admin"))):
    return {"events": list_audit_events(limit, principal.tenant_id)}


@router.get("/api/admin/audit/verify")
def admin_audit_verify(principal=Depends(require_access("admin"))):
    return verify_audit_chain(principal.tenant_id)


@router.get("/api/admin/requests")
def admin_request_log(limit: int = 100, principal=Depends(require_access("admin"))):
    return {"requests": recent_requests(limit)}


@router.get(
    "/report",
    response_class=HTMLResponse,
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def get_report():
    report_path = SCANS_DIR / "report.html"
    if not report_path.exists():
        return HTMLResponse("<h1>Report not found</h1><p>Please run the security scans first.</p>", status_code=404)
    return HTMLResponse(report_path.read_text())

@router.get(
    "/download-sbom",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def download_sbom():
    sbom_path = SCANS_DIR / "sbom.json"
    if not sbom_path.exists():
        from policy_engine import generate_cyclonedx_sbom
        from .dependencies import discover_dependency_manifests
        try:
            generate_cyclonedx_sbom(discover_dependency_manifests(PROJECT_ROOT), sbom_path)
        except Exception:
            logger.exception("SBOM generation failed")
            raise HTTPException(
                status_code=500, detail="SBOM generation failed. Check server logs."
            )
            
    return FileResponse(
        str(sbom_path),
        media_type="application/json",
        filename="cyclonedx-sbom.json"
    )


@router.get(
    "/download-report-bundle",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
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

@router.post(
    "/toggle-waf",
    dependencies=[Depends(require_demo_boundary), Depends(require_recent_access("admin"))],
)
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    set_application_state("waf_enabled", WAF_ENABLED)
    return {"status": "success", "waf_enabled": WAF_ENABLED}

@router.get(
    "/get-waf-rules",
    dependencies=[Depends(require_demo_boundary), Depends(require_role("viewer"))],
)
def get_waf_rules():
    global WAF_ENABLED
    rules = load_waf_rules_from_db()
    return {"status": "success", "rules": rules, "waf_enabled": WAF_ENABLED}

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
    global WAF_ENABLED
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
    
    score = calculate_exploitability_score(SCANS_DIR, WAF_ENABLED)
    
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
        "waf_enabled": WAF_ENABLED,
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
    from .worker import async_scan_task

    payload = ScanJobPayload(
        job_id=job_id,
        target=target_name,
        custom_file_path=custom_file_path,
        waf_enabled=WAF_ENABLED,
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
    if not DEMO_LAB_ENABLED:
        await websocket.close(code=4404, reason="Aegis demo lab is disabled")
        return
    if not _connection_is_loopback(websocket):
        await websocket.close(code=4403, reason="Aegis demo lab is local-only")
        return
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

@router.get(
    "/export-dossier",
    dependencies=[Depends(require_demo_boundary), Depends(require_access("admin"))],
)
def export_dossier():
    reports = {
        name: load_json_report(SCANS_DIR / filename)
        for name, filename in {
            "ruff": "ruff-report.json",
            "semgrep": "semgrep-report.json",
            "safety": "safety-report.json",
            "osv": "osv-report.json",
            "trivy": "trivy-report.json",
            "secrets": "secrets-report.json",  # pragma: allowlist secret
            "yara": "yara-report.json",
            "clamav": "clamav-report.json",
            "zap": "zap-report.json",
            "iac": "iac-report.json",
        }.items()
    }
    results = analyze_report_set(reports)
    result_by_tool = {result["tool"]: result for result in results}

    def metrics(tool: str) -> tuple[str, int, int]:
        result = result_by_tool[tool]
        return result["status"], result["total_issues"], result["blocking_issues"]

    ruff_report = reports["ruff"]
    semgrep_report = reports["semgrep"]
    safety_report = reports["safety"]
    trivy_report = reports["trivy"]
    secrets_report = reports["secrets"]
    yara_report = reports["yara"]
    clamav_report = reports["clamav"]
    zap_report = reports["zap"]
    iac_report = reports["iac"]

    ruff_status, ruff_total, ruff_blocking = metrics("Ruff (SAST)")
    semgrep_status, semgrep_total, semgrep_blocking = metrics("Semgrep")
    safety_status, safety_total, safety_blocking = metrics("Safety")
    trivy_status, trivy_total, trivy_blocking = metrics("Trivy")
    secrets_status, secrets_total, secrets_blocking = metrics("Secrets Scanner")
    yara_status, yara_total, yara_blocking = metrics("YARA Scanner")
    clamav_status, clamav_total, clamav_blocking = metrics("ClamAV")
    zap_status, zap_total, zap_blocking = metrics("Aegis DAST Probe")
    iac_status, iac_total, iac_blocking = metrics("IaC")

    iac_findings_list = (
        [item for item in iac_report.get("findings", []) if isinstance(item, dict)]
        if isinstance(iac_report, dict)
        else []
    )
    iac_suppressions_list = (
        [
            item
            for item in iac_report.get("unmanaged_suppressions", [])
            if isinstance(item, dict)
        ]
        if isinstance(iac_report, dict)
        else []
    )

    decision = evaluate_policy_results(results)
    gate_decision = decision["status"]
    reason = decision["reason"]

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

    # Format IaC (Checkov)
    iac_findings_text = ""
    if iac_findings_list or iac_suppressions_list:
        for finding in [*iac_findings_list, *iac_suppressions_list][:10]:
            iac_findings_text += f"  - ID: {finding.get('rule_id')} | Severity: {finding.get('severity', 'MEDIUM')}\n"
            iac_findings_text += f"    Framework: {finding.get('framework')} | Resource: {finding.get('resource') or 'n/a'}\n"
            iac_findings_text += f"    Location: {finding.get('path') or 'n/a'}:{finding.get('start_line') or 1}-{finding.get('end_line') or finding.get('start_line') or 1}\n"
            iac_findings_text += f"    Remediation: {finding.get('remediation') or finding.get('comment') or finding.get('title') or 'Review the Checkov finding.'}\n"
            iac_findings_text += "  ------------------------------------------------------------------\n"
    elif iac_status == "MISSING":
        iac_findings_text = "  No report file found.\n"
    else:
        iac_findings_text = "  No IaC findings detected.\n"

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

[6.5] INFRASTRUCTURE-AS-CODE CONFIGURATION - CHECKOV
--------------------------------------------------------------------------------
Status: {iac_status}
Total Issues Detected: {iac_total}
Blocking Issues: {iac_blocking}

FINDINGS:
{iac_findings_text}

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

app = create_app()


if __name__ == "__main__":
    import uvicorn
    host = validate_server_bind(
        os.environ.get("AEGIS_HOST", "127.0.0.1"),
        auth_required=AUTH_REQUIRED,
    )
    uvicorn.run("app.main:app", host=host, port=5001, reload=False)
