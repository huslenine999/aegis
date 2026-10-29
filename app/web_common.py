"""Shared web application state and access-control primitives.

Route modules under ``app.routes`` and the application factory in
``app.main`` both consume this module so that security-relevant helpers,
constants, and mutable runtime flags have exactly one definition.
"""

import hmac
import ipaddress
import os
from typing import Any

from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates

from .auth import (
    AUTH_REQUIRED,
    SESSION_COOKIE,
    require_role,
    session_authentication_is_recent,
)
from .config import environment_positive_int
from .database import BASE_DIR, get_application_state

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


async def json_object(request: Request) -> Any:
    """Parse a request body that must be a JSON object, rejecting anything else with 400."""
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="JSON object body required.") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="JSON object body required.")
    return body

DEV_ADMIN_TOKEN = os.environ.get("AEGIS_DEV_ADMIN_TOKEN")
MAX_UPLOAD_BYTES = environment_positive_int("AEGIS_MAX_UPLOAD_BYTES", 1024 * 1024)
MAX_REQUEST_BYTES = environment_positive_int(
    "AEGIS_MAX_REQUEST_BYTES", MAX_UPLOAD_BYTES + 64 * 1024
)
SCAN_JOB_TIMEOUT_SECONDS = environment_positive_int(
    "AEGIS_SCAN_JOB_TIMEOUT_SECONDS", 3600
)
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
    "codeql.sarif": "application/sarif+json",
    "codeql-report.json": "application/json",
    "clamav-report.json": "application/json",
    "zap-report.json": "application/json",
    "iac-report.json": "application/json",
    "sandbox-status.json": "application/json",
    "source-descriptor.json": "application/json",
    "scan-manifest.json": "application/json",
}

def parse_cors_origins() -> list[str]:
    raw_origins = os.environ.get(
        "AEGIS_CORS_ORIGINS", "http://127.0.0.1:5001,http://localhost:5001"
    )
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


def setup_is_available() -> bool:
    return bool(os.environ.get("AEGIS_SETUP_TOKEN")) and not bool(
        get_application_state("setup_completed", False)
    )


def _connection_is_loopback(connection: Request) -> bool:
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
