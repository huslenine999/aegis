import asyncio
import logging
import os
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from ..audit import record_audit
from ..auth import SESSION_COOKIE, Principal, require_role
from ..github_integration import (
    begin_oauth,
    complete_oauth,
    create_check_run,
    disconnect_github,
    github_app_enabled,
    github_connection,
    github_enabled,
    github_webhook_enabled,
    list_repositories,
    mark_webhook_delivery,
    verify_and_record_webhook,
)
from ..github_lifecycle import (
    GitHubLifecycleError,
    resolve_github_webhook_binding,
    revoke_github_capabilities,
)
from ..projects import create_project, get_project
from ..web_common import require_access, require_recent_access
from .project_routes import _enqueue_project_scan

router = APIRouter()
logger = logging.getLogger("aegis.main")


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
    should_scan = (
        delivery["event_type"] == "pull_request"
        and delivery["action"] in {"opened", "reopened", "synchronize"}
    )
    if should_scan:
        try:
            route = resolve_github_webhook_binding(
                repository_full_name=delivery["repository"],
                repository_id=delivery["repository_id"],
                installation_id=delivery["installation_id"],
            )
        except GitHubLifecycleError as exc:
            mark_webhook_delivery(delivery["delivery_id"], "failed")
            record_audit(
                None,
                "github.webhook_unbound",
                "github_delivery",
                delivery["delivery_id"],
                {"error_type": type(exc).__name__},
            )
            raise HTTPException(
                status_code=409,
                detail="GitHub repository is not bound to an active tenant.",
            ) from exc
        tenant_id = route["tenant_id"]
        project = get_project(route["project_id"], tenant_id)
        project_owner = Principal(
            route["created_by"],
            route["username"],
            route["role"],
            "",
            tenant_id,
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
        if delivery["event_type"] == "installation" and delivery["action"] in {
            "deleted",
            "suspend",
            "suspended",
        }:
            if delivery["installation_id"] < 1:
                raise ValueError("GitHub installation context is invalid.")
            revoke_github_capabilities(installation_id=delivery["installation_id"])
            mark_webhook_delivery(delivery["delivery_id"], "processed")
            record_audit(
                None,
                "github.installation.revoked",
                "github_installation",
                delivery["installation_id"],
                {"delivery_id": delivery["delivery_id"]},
                tenant_id=tenant_id,
            )
        elif not should_scan or not project or not project_owner:
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
                tenant_id=tenant_id,
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
    session_token = request.cookies.get(SESSION_COOKIE, "")
    if not session_token:
        raise HTTPException(
            status_code=401,
            detail="GitHub OAuth requires a browser session.",
        )
    try:
        url = begin_oauth(
            principal.user_id,
            _github_callback_url(request),
            session_token,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return RedirectResponse(url, status_code=302)


@router.get("/api/github/callback", name="github_callback")
def github_callback(request: Request, code: str = "", state: str = ""):
    session_token = request.cookies.get(SESSION_COOKIE, "")
    if not code or not state or not session_token:
        return RedirectResponse("/projects?github=denied", status_code=303)
    try:
        complete_oauth(
            code,
            state,
            _github_callback_url(request),
            session_token,
        )
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
