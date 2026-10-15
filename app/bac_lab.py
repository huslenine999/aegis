"""Isolated, synthetic broken-access-control research lab; never a production app."""

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Annotated

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field


ACTORS = MappingProxyType({"alice": "user", "bob": "user", "admin": "admin", "guest": "guest"})
_MAX_EVENTS = 4096
_CORRELATION_PATTERN = r"^[A-Za-z0-9_.-]{1,128}$"
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")
_START_SECONDS = 5.0
_STOP_SECONDS = 3.0
Identifier = Annotated[str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]


class DocumentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=200, strict=True, pattern=r"\S")


def _seed() -> dict:
    documents = {
        document_id: {
            "id": document_id,
            "owner": owner,
            "public": suffix == "public",
            "title": f"{owner.title()} {suffix} document",
            "content": f"synthetic-canary:{document_id}:no-real-data",
        }
        for owner in ("alice", "bob")
        for suffix in ("private-1", "private-2", "public")
        for document_id in (f"{owner}-{suffix}",)
    }
    users = {
        actor: {
            "id": actor,
            "role": role,
            "active": True,
            "private_marker": "synthetic-admin-marker" if actor == "admin" else f"synthetic-user-{actor}-marker",
        }
        for actor, role in ACTORS.items()
        if actor != "guest"
    }
    return {"documents": documents, "users": users}


def create_bac_app(*, mode: str, tokens: Mapping[str, str], control_token: str, instance_id: str) -> FastAPI:
    """Create independent in-memory lab state and a separate instrumented oracle."""
    if os.environ.get("AEGIS_ENV", "").strip().lower() == "production":
        raise ValueError("The BAC research lab is disabled in production")
    if mode not in {"fixed", "vulnerable"}:
        raise ValueError("BAC lab mode must be fixed or vulnerable")
    if not isinstance(tokens, Mapping) or set(tokens) != {"alice", "bob", "admin"}:
        raise ValueError("BAC lab tokens must contain exactly alice, bob and admin")
    supplied_tokens = (*tokens.values(), control_token)
    if any(not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token) for token in supplied_tokens):
        raise ValueError("BAC lab credentials must be nonempty bounded header-safe tokens")
    if len(set(supplied_tokens)) != 4:
        raise ValueError("BAC actor tokens and research control key must be unique")
    if not isinstance(instance_id, str) or not re.fullmatch(_CORRELATION_PATTERN, instance_id):
        raise ValueError("BAC lab instance ID must be bounded and header-safe")

    credentials = dict(tokens)
    state = _seed()
    seed_sha256 = hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    events: tuple[dict, ...] = ()
    lock = threading.RLock()
    app = FastAPI(title="Aegis synthetic BAC lab", docs_url=None, redoc_url=None, openapi_url=None)

    def identity(request: Request) -> str:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.isascii() or len(token) > 256:
            return "guest"
        return next((actor for actor, expected in credentials.items() if hmac.compare_digest(token, expected)), "guest")

    def actor_for(request: Request, *, required: bool = False) -> str:
        actor = identity(request)
        if actor == "guest":
            if required or "authorization" in request.headers:
                raise HTTPException(status_code=401, detail="Valid bearer authentication is required")
            return actor
        with lock:
            if not state["users"][actor]["active"]:
                raise HTTPException(status_code=401, detail="Actor is inactive")
        return actor

    def redacted(value: str) -> str:
        for secret in supplied_tokens:
            value = value.replace(secret, "[redacted]")
        return value

    def correlation(request: Request, header: str, default: str) -> tuple[str, bool]:
        value = request.headers.get(header)
        if value is None:
            return default, True
        valid = bool(re.fullmatch(_CORRELATION_PATTERN, value)) and all(secret not in value for secret in supplied_tokens)
        return (value if valid else default), valid

    @app.middleware("http")
    async def audit_business_requests(request: Request, call_next):
        nonlocal events
        path = request.url.path
        business_request = path in {"/me", "/documents"} or path.startswith(("/documents/", "/admin/"))
        if not business_request:
            return await call_next(request)
        request_id, valid_request_id = correlation(request, "X-Aegis-Request-ID", secrets.token_hex(16))
        case_id, valid_case_id = correlation(request, "X-Aegis-Case-ID", "")
        actor = identity(request)
        response = (
            await call_next(request)
            if valid_request_id and valid_case_id
            else JSONResponse(status_code=400, content={"detail": "Invalid research correlation header"})
        )
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "request_id": request_id,
            "case_id": case_id,
            "actor": actor,
            "method": request.method,
            "path": redacted(path[:512]),
            "status_code": response.status_code,
        }
        with lock:
            events = (*events, event)[-_MAX_EVENTS:]
        return response

    def document_for(document_id: str) -> dict:
        document = state["documents"].get(document_id)
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")
        return document

    def may_read(actor: str, document: dict) -> bool:
        return document["public"] or actor == "admin" or actor == document["owner"] or (mode == "vulnerable" and actor != "guest")

    def require_mutation(actor: str, document: dict) -> None:
        if mode == "fixed" and actor not in {"admin", document["owner"]}:
            raise HTTPException(status_code=403, detail="Document ownership is required")

    def require_admin(actor: str) -> None:
        if mode == "fixed" and actor != "admin":
            raise HTTPException(status_code=403, detail="Administrator role is required")

    @app.get("/me")
    def me(request: Request):
        actor = actor_for(request, required=True)
        return {"actor": actor, "role": ACTORS[actor]}

    @app.get("/documents/{document_id}")
    def read_document(document_id: Identifier, request: Request):
        with lock:
            actor = actor_for(request)
            document = document_for(document_id)
            if not may_read(actor, document):
                raise HTTPException(status_code=403, detail="Document access is denied")
            return dict(document)

    @app.get("/documents/{document_id}/preview")
    def preview_document(document_id: Identifier, request: Request):
        with lock:
            actor = actor_for(request)
            document = document_for(document_id)
            if not may_read(actor, document):
                return {"id": document["id"], "title": document["title"]}
            return dict(document)

    @app.get("/documents")
    def list_documents(request: Request):
        with lock:
            actor = actor_for(request)
            return {"documents": [dict(document) for document in state["documents"].values() if may_read(actor, document)]}

    @app.get("/documents/{document_id}/export")
    def export_document(document_id: Identifier, request: Request):
        with lock:
            actor = actor_for(request)
            document = document_for(document_id)
            if document["public"] or actor in {"admin", document["owner"]}:
                return dict(document)
            # Seeded bug: the denial is correct, but its error body leaks the record.
            leak = {"document": dict(document)} if mode == "vulnerable" and actor != "guest" else {}
            return JSONResponse(status_code=403, content={"detail": "Document export is denied", **leak})

    @app.put("/documents/{document_id}/title")
    def rename_document(document_id: Identifier, payload: DocumentPatch, request: Request):
        nonlocal state
        with lock:
            actor = actor_for(request, required=True)
            document = document_for(document_id)
            allowed = actor in {"admin", document["owner"]}
            if mode == "fixed" and not allowed:
                raise HTTPException(status_code=403, detail="Document ownership is required")
            # Seeded bug: the vulnerable route writes before it checks ownership.
            updated = {**document, "title": payload.title}
            state = {**state, "documents": {**state["documents"], document_id: updated}}
            if not allowed:
                raise HTTPException(status_code=403, detail="Document ownership is required")
            return dict(updated)

    @app.patch("/documents/{document_id}")
    def update_document(document_id: Identifier, payload: DocumentPatch, request: Request):
        nonlocal state
        with lock:
            actor = actor_for(request, required=True)
            document = document_for(document_id)
            require_mutation(actor, document)
            updated = {**document, "title": payload.title}
            state = {**state, "documents": {**state["documents"], document_id: updated}}
            return dict(updated)

    @app.delete("/documents/{document_id}")
    def delete_document(document_id: Identifier, request: Request):
        nonlocal state
        with lock:
            actor = actor_for(request, required=True)
            document = document_for(document_id)
            require_mutation(actor, document)
            state = {**state, "documents": {key: value for key, value in state["documents"].items() if key != document_id}}
            return {"deleted": document_id}

    @app.get("/admin/users")
    def read_users(request: Request):
        with lock:
            actor = actor_for(request, required=True)
            require_admin(actor)
            return {"users": [dict(user) for user in state["users"].values()], "private_marker": state["users"]["admin"]["private_marker"]}

    @app.post("/admin/users/{user_id}/disable")
    def disable_user(user_id: Identifier, request: Request):
        nonlocal state
        with lock:
            actor = actor_for(request, required=True)
            require_admin(actor)
            user = state["users"].get(user_id)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")
            updated = {**user, "active": False}
            state = {**state, "users": {**state["users"], user_id: updated}}
            return dict(updated)

    def require_control(request: Request) -> None:
        provided = request.headers.get("X-Aegis-Lab-Key", "")
        if not provided.isascii() or len(provided) > 256 or not hmac.compare_digest(provided, control_token):
            raise HTTPException(status_code=401, detail="Research control key is required")

    research = APIRouter(prefix="/_research", dependencies=[Depends(require_control)])

    @research.get("/info")
    def info():
        return {"lab": "aegis-bac-v2", "instance_id": instance_id, "mode": mode, "seed_sha256": seed_sha256}

    @research.post("/reset")
    def reset():
        nonlocal state
        with lock:
            state = _seed()
        return {"reset": True}

    @research.get("/snapshot")
    def snapshot():
        with lock:
            return {collection: {key: dict(value) for key, value in state[collection].items()} for collection in ("documents", "users")}

    @research.get("/events")
    def audit_events(case_id: Annotated[str | None, Query(min_length=1, max_length=128, pattern=_CORRELATION_PATTERN)] = None):
        with lock:
            return {"events": [dict(event) for event in events if case_id is None or event["case_id"] == case_id]}

    app.include_router(research)
    return app


@dataclass(frozen=True)
class RunningLab:
    base_url: str
    tokens: Mapping[str, str]
    control_token: str
    instance_id: str
    mode: str


@contextmanager
def local_bac_lab(mode: str) -> Iterator[RunningLab]:
    """Bind a newly owned loopback socket; never target or publish an existing app."""
    tokens = MappingProxyType({actor: secrets.token_urlsafe(32) for actor in ("alice", "bob", "admin")})
    control_token = secrets.token_urlsafe(32)
    instance_id = secrets.token_hex(16)
    app = create_bac_app(mode=mode, tokens=tokens, control_token=control_token, instance_id=instance_id)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = None
    thread = None
    startup_failure: BaseException | None = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(
            app, host="127.0.0.1", port=port, loop="asyncio", lifespan="off", access_log=False,
            log_level="error", timeout_keep_alive=1, timeout_graceful_shutdown=1,
        ))

        def serve():
            nonlocal startup_failure
            try:
                server.run(sockets=[listener])
            except BaseException as exc:
                startup_failure = exc

        thread = threading.Thread(target=serve, name=f"aegis-bac-{instance_id[:8]}", daemon=True)
        thread.start()
        deadline = time.monotonic() + _START_SECONDS
        while not server.started:
            if startup_failure is not None or not thread.is_alive():
                raise RuntimeError("BAC lab server failed to start") from startup_failure
            if time.monotonic() >= deadline:
                raise RuntimeError("BAC lab server startup timed out")
            thread.join(0.01)
        yield RunningLab(f"http://127.0.0.1:{port}", tokens, control_token, instance_id, mode)
    finally:
        if server is not None:
            server.should_exit = True
        if thread is not None and server is not None and thread.ident is not None:
            thread.join(_STOP_SECONDS)
            if thread.is_alive():
                server.force_exit = True
                listener.close()
                thread.join(0.5)
            if thread.is_alive():
                raise RuntimeError("BAC lab server shutdown timed out")
        listener.close()
