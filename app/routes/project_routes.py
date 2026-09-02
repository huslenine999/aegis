import asyncio
import logging
import re
import shutil
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..artifact_storage import project_directory
from ..audit import record_audit
from ..auth import AUTH_REQUIRED, principal_from_request, require_role
from ..database import REDIS_AVAILABLE, REDIS_URL, SCANS_DIR, redis_client
from ..findings import get_finding, list_findings, update_finding
from ..github_integration import create_repository_issue
from ..notifications import (
    CHANNEL_TYPES,
    create_channel,
    delete_channel,
    list_channels,
    queue_test_channel,
)
from ..policies import (
    active_policy,
    approve_policy,
    create_policy,
    ensure_active_policy,
    list_policies,
    normalize_definition,
    simulate_policy,
)
from ..projects import (
    VALID_PRESETS,
    create_project,
    create_scan_run,
    delete_project,
    get_project,
    get_scan_run,
    list_projects,
    list_project_members,
    list_scan_runs,
    normalize_github_repository_url,
    remove_project_member,
    require_project_role,
    set_project_member,
    update_project,
)
from ..scan_engine import ScanJobPayload
from ..web_common import (
    DEMO_LAB_ENABLED,
    SCAN_JOB_TIMEOUT_SECONDS,
    require_access,
    require_recent_access,
    templates,
)
from .. import web_common

router = APIRouter()
logger = logging.getLogger("aegis.main")


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
    project: dict,
    principal,
    preset: str,
    github_context: dict | None = None,
    diff_aware: bool = False,
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
    from ..worker import async_scan_task

    payload = ScanJobPayload(
        job_id=job_id,
        target="project",
        waf_enabled=web_common.WAF_ENABLED,
        scan_run_id=run_id,
        project_id=project["id"],
        requested_by=principal.user_id,
        preset=preset,
        source_revision=(github_context or {}).get("head_sha"),
        github_installation_id=(github_context or {}).get("installation_id"),
        # Pull-request checks gate on newly introduced findings only.
        diff_aware=diff_aware or bool((github_context or {}).get("pull_request")),
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


@router.get("/api/projects/{project_id}/scans/{run_id}")
def project_scan_detail(
    project_id: int, run_id: int, principal=Depends(require_role("viewer"))
):
    return _authorized_scan(project_id, run_id, principal)


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
    diff_aware = bool(body.get("diff_aware", False))
    return _enqueue_project_scan(project, principal, preset, diff_aware=diff_aware)


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
