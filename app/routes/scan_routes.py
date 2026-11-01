import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..auth import websocket_principal
from ..database import redis_client
from ..rate_limit import allow_websocket
from ..web_common import SCAN_JOB_TIMEOUT_SECONDS
from ..projects import require_project_role

router = APIRouter()
logger = logging.getLogger("aegis.main")

FINAL_STATES = ("completed", "failed", "cancelled")
POLL_SECONDS = 0.1
STATE_CHECK_SECONDS = 5.0
STREAM_GRACE_SECONDS = 300


@router.websocket("/ws/scan/{job_id}")
async def websocket_scan(websocket: WebSocket, job_id: str):
    """Stream an authorized project scan."""
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
    project_value = redis_client.hget(f"job:{job_id}", "project_id")
    if project_value:
        project_id = int(
            project_value.decode() if isinstance(project_value, bytes) else project_value
        )
        try:
            require_project_role(
                project_id,
                principal.user_id,
                principal.role,
                "viewer",
                principal.tenant_id,
            )
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
    
    try:
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
            state_text = state.decode('utf-8')
            await websocket.send_json({
                "type": "state",
                "state": state_text,
                "progress": int(progress) if progress else 0
            })
            if state_text in FINAL_STATES:
                return  # Nothing more will be published for this job.

        # 3. Stream updates. get_message(timeout=0) never blocks, so the event
        # loop that serves every request is never held by this stream. A
        # periodic look at the stored state, and a hard deadline, end streams
        # whose final message was never published.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + SCAN_JOB_TIMEOUT_SECONDS + STREAM_GRACE_SECONDS
        next_state_check = loop.time() + STATE_CHECK_SECONDS
        while loop.time() < deadline:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=0)
            if message:
                data = json.loads(message['data'].decode('utf-8'))
                await websocket.send_json(data)
                if data.get("type") == "state" and data.get("state") in FINAL_STATES:
                    break
                continue
            if loop.time() >= next_state_check:
                next_state_check = loop.time() + STATE_CHECK_SECONDS
                stored = r_conn.hget(job_key, "state")
                if stored and stored.decode('utf-8') in FINAL_STATES:
                    await websocket.send_json({
                        "type": "state",
                        "state": stored.decode('utf-8'),
                        "progress": 100,
                    })
                    break
            await asyncio.sleep(POLL_SECONDS)
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe(f"job_channel:{job_id}")
        pubsub.close()
