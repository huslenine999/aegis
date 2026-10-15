import logging
import os
import shutil

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ..audit import create_audit_checkpoint, list_audit_events, verify_audit_chain
from ..database import REDIS_AVAILABLE, SCANS_DIR, get_connection, redis_client
from ..github_integration import github_enabled
from ..observability import recent_requests
from ..web_common import DEMO_LAB_ENABLED, json_object, require_access, templates

router = APIRouter()
logger = logging.getLogger("aegis.main")


@router.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, principal=Depends(require_access("admin"))):
    return templates.TemplateResponse(request, "admin.html")


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
        "scanner_deep": "requires an isolated CodeQL runtime",
    }


@router.get("/api/admin/audit")
def admin_audit(limit: int = 100, principal=Depends(require_access("admin"))):
    return {"events": list_audit_events(limit, principal.tenant_id)}


@router.get("/api/admin/audit/verify")
def admin_audit_verify(principal=Depends(require_access("admin"))):
    return verify_audit_chain(principal.tenant_id)


@router.post("/api/admin/audit/verify")
async def admin_audit_verify_checkpoints(request: Request, principal=Depends(require_access("admin"))):
    """Verify the chain against checkpoints exported earlier and stored outside Aegis."""
    body = await json_object(request)
    checkpoints = body.get("checkpoints")
    if not isinstance(checkpoints, list) or not 1 <= len(checkpoints) <= 1000:
        raise HTTPException(status_code=400, detail="Provide 1 to 1000 checkpoints.")
    return verify_audit_chain(principal.tenant_id, checkpoints)


@router.get("/api/admin/audit/checkpoint")
def admin_audit_checkpoint(principal=Depends(require_access("admin"))):
    """Export the current chain head for storage outside Aegis."""
    try:
        return create_audit_checkpoint(principal.tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api/admin/requests")
def admin_request_log(limit: int = 100, principal=Depends(require_access("admin"))):
    return {"requests": recent_requests(limit)}
