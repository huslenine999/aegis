"""Shared web application state and access-control primitives.

Route modules under ``app.routes`` and the application factory in
``app.main`` both consume this module so that security-relevant helpers,
constants, and mutable runtime flags have exactly one definition.
"""

import hmac
import ipaddress
import os

from fastapi import Depends, HTTPException, Request, WebSocket
from fastapi.templating import Jinja2Templates

from .auth import (
    AUTH_REQUIRED,
    SESSION_COOKIE,
    require_role,
    session_authentication_is_recent,
)
from .config import environment_positive_int
from .database import BASE_DIR, PROJECT_ROOT, get_application_state
from .reporting import (
    generate_fallback_tree as generate_project_fallback_tree,
)
from .waf_rules import load_waf_rules_with_defaults

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

DEMO_LAB_ENABLED = os.environ.get(
    "AEGIS_ENABLE_DEMO_LAB", "false"
).lower() in {"1", "true", "yes", "on"}
DEV_ADMIN_TOKEN = os.environ.get("AEGIS_DEV_ADMIN_TOKEN")
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
    "source-descriptor.json": "application/json",
    "scan-manifest.json": "application/json",
}
COMMERCIAL_CONTACT_URL = os.environ.get(
    "AEGIS_COMMERCIAL_CONTACT_URL",
    "https://github.com/huslenine999/aegis/issues/new",
)

# Global state for the WAF toggle (demo only).
WAF_ENABLED = os.environ.get("WAF_ENABLED", "false").lower() == "true"


def parse_cors_origins() -> list[str]:
    raw_origins = os.environ.get(
        "AEGIS_CORS_ORIGINS", "http://127.0.0.1:5001,http://localhost:5001"
    )
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


def setup_is_available() -> bool:
    return bool(os.environ.get("AEGIS_SETUP_TOKEN")) and not bool(
        get_application_state("setup_completed", False)
    )


def generate_fallback_tree():
    return generate_project_fallback_tree(PROJECT_ROOT)


def load_waf_rules_from_db():
    return load_waf_rules_with_defaults()


def require_demo_lab_enabled():
    if not DEMO_LAB_ENABLED:
        raise HTTPException(
            status_code=404,
            detail="Aegis demo lab is disabled. Set AEGIS_ENABLE_DEMO_LAB=true to enable vulnerable training routes.",
        )


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


def require_access(minimum_role: str):
    role_dependency = require_role(minimum_role)

    def dependency(request: Request):
        if (
            not AUTH_REQUIRED
            and DEV_ADMIN_TOKEN
            and minimum_role in {"operator", "admin"}
            and not _connection_is_loopback(request)
        ):
            raise HTTPException(status_code=401, detail="Protected actions are local-only.")
        if not AUTH_REQUIRED and DEV_ADMIN_TOKEN and minimum_role in {"operator", "admin"}:
            supplied = request.headers.get("X-Aegis-Token", "")
            if not supplied or not hmac.compare_digest(supplied, DEV_ADMIN_TOKEN):
                raise HTTPException(status_code=401, detail="Missing or invalid Aegis admin token.")
        return role_dependency(request)

    return dependency


def require_demo_boundary(request: Request) -> None:
    """Keep every legacy threat-lab surface local and explicitly enabled."""

    require_demo_lab_enabled()
    if not _connection_is_loopback(request):
        raise HTTPException(
            status_code=403,
            detail="The Aegis demo lab is available only from a loopback client.",
        )


def require_demo_lab_access(
    request: Request,
    principal=Depends(require_access("admin")),
):
    require_demo_boundary(request)
    return principal


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
