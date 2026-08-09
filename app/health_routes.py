"""Health, readiness, metrics, and security contact endpoints."""

import hmac
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from .auth import principal_from_request
from .database import REDIS_AVAILABLE, get_connection, redis_client
from .observability import render_metrics


router = APIRouter()


@router.get("/health")
def health():
    return {
        "status": "running",
        "service": "aegis-security-console",
        "demo_lab_enabled": os.environ.get("AEGIS_ENABLE_DEMO_LAB", "false").lower()
        in {"1", "true", "yes", "on"},
    }


@router.get("/.well-known/security.txt", response_class=PlainTextResponse)
def security_txt():
    contact = os.environ.get(
        "AEGIS_SECURITY_CONTACT",
        "https://github.com/huslenine999/aegis/security/advisories/new",
    )
    policy = os.environ.get(
        "AEGIS_SECURITY_POLICY_URL",
        "https://github.com/huslenine999/aegis/security/policy",
    )
    if not contact.startswith(("https://", "mailto:")) or any(
        value in contact for value in ("\r", "\n")
    ):
        contact = "https://github.com/huslenine999/aegis/security/advisories/new"
    if not policy.startswith("https://") or any(
        value in policy for value in ("\r", "\n")
    ):
        policy = "https://github.com/huslenine999/aegis/security/policy"
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    lines = [
        f"Contact: {contact}",
        f"Expires: {expires}",
        "Preferred-Languages: en",
        f"Policy: {policy}",
    ]
    public_url = os.environ.get("AEGIS_PUBLIC_URL", "").rstrip("/")
    if public_url.startswith("https://"):
        lines.append(f"Canonical: {public_url}/.well-known/security.txt")
    return "\n".join(lines) + "\n"


@router.get("/ready")
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
    notifier_state = "not-required"
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

            workers = Worker.all(connection=redis_client)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Worker readiness could not be verified.",
            ) from exc
        scan_workers = [worker for worker in workers if "default" in worker.queue_names()]
        if not scan_workers:
            raise HTTPException(status_code=503, detail="No scanner RQ workers are available.")
        worker_state = f"{len(scan_workers)} available"
        if os.environ.get("AEGIS_ALLOW_DEEP_SCANS", "false").lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            isolated_workers = [
                worker
                for worker in workers
                if "deep" in worker.queue_names()
                and str(getattr(worker, "name", "")).startswith("aegis-isolated-")
            ]
            if not isolated_workers:
                raise HTTPException(
                    status_code=503,
                    detail="No isolated deep-scan workers are available.",
                )
            worker_state += f", {len(isolated_workers)} isolated"

    notifier_required = os.environ.get("AEGIS_REQUIRE_NOTIFIER", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if notifier_required:
        if not REDIS_AVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="Notifier readiness requires Redis.",
            )
        try:
            from rq import Worker

            workers = Worker.all(connection=redis_client)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Notifier readiness could not be verified.",
            ) from exc
        notifier_workers = [
            worker for worker in workers if "notifications" in worker.queue_names()
        ]
        if not notifier_workers:
            raise HTTPException(
                status_code=503,
                detail="No notifier RQ workers are available.",
            )
        notifier_state = f"{len(notifier_workers)} available"

    return {
        "status": "ready",
        "service": "aegis-security-console",
        "redis": redis_state,
        "worker": worker_state,
        "notifier": notifier_state,
    }


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    metrics_token = os.environ.get("AEGIS_METRICS_TOKEN", "")
    supplied = request.headers.get("authorization", "")
    token_valid = (
        metrics_token
        and supplied.startswith("Bearer ")
        and hmac.compare_digest(supplied[7:].strip(), metrics_token)
    )
    principal = principal_from_request(request)
    principal_valid = bool(
        principal
        and principal.role == "admin"
        and (
            principal.auth_method != "token"
            or "*" in principal.scopes
            or "admin" in principal.scopes
        )
    )
    if not token_valid and not principal_valid:
        raise HTTPException(status_code=401, detail="Metrics authentication required.")
    return PlainTextResponse(render_metrics(), media_type="text/plain; version=0.0.4")
