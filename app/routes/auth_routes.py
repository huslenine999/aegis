import asyncio
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..audit import record_audit
from ..auth import (
    API_TOKEN_HASH_SCHEME,
    AUTH_REQUIRED,
    SESSION_COOKIE,
    TOKEN_SCOPES,
    authenticate,
    begin_mfa_setup,
    complete_initial_setup,
    confirm_mfa_setup,
    create_session,
    disable_mfa,
    hash_api_token,
    hash_password,
    principal_from_request,
    require_role,
    reauthenticate_session,
    revoke_session,
    revoke_user_sessions,
)
from ..database import get_application_state, get_connection
from ..github_lifecycle import revoke_github_capabilities
from ..oidc import (
    OIDC_BINDING_COOKIE,
    OIDC_TRANSACTION_TTL_SECONDS,
    begin_oidc,
    complete_oidc,
    new_browser_binding,
    oidc_enabled,
)
from ..projects import create_project, normalize_github_repository_url
from ..web_common import (
    require_access,
    require_recent_access,
    setup_is_available,
    templates,
)

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    if setup_is_available():
        return RedirectResponse("/setup", status_code=303)
    if AUTH_REQUIRED and not principal_from_request(request):
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/projects", status_code=303)


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
    browser_binding = new_browser_binding()
    try:
        authorization_url = begin_oidc(
            _oidc_callback_url(request),
            return_to,
            browser_binding=browser_binding,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    response = RedirectResponse(authorization_url, status_code=303)
    response.set_cookie(
        OIDC_BINDING_COOKIE,
        browser_binding,
        httponly=True,
        secure=os.environ.get("AEGIS_ENV", "development").lower() == "production",
        samesite="lax",
        max_age=OIDC_TRANSACTION_TTL_SECONDS,
        path="/",
    )
    return response


@router.get("/api/auth/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, code: str = "", state: str = ""):
    if not code or not state:
        raise HTTPException(status_code=400, detail="OIDC callback is incomplete.")
    try:
        principal, return_to = await asyncio.to_thread(
            complete_oidc,
            code,
            state,
            _oidc_callback_url(request),
            browser_binding=request.cookies.get(OIDC_BINDING_COOKIE, ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="OIDC login failed.") from exc
    record_audit(principal.user_id, "auth.oidc_login_succeeded", "session")
    response = RedirectResponse(return_to, status_code=303)
    response.delete_cookie(OIDC_BINDING_COOKIE, path="/")
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
    if active is False:
        revoke_github_capabilities(user_id=user_id)
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
               (user_id, token_hash, hash_scheme, revoked_at, name,
                expires_at, created_at, scopes)
               VALUES (?, ?, ?, NULL, ?, ?, ?, ?)""",
            (
                user_id,
                hash_api_token(token),
                API_TOKEN_HASH_SCHEME,
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
