import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..auth import websocket_principal
from ..database import redis_client
from ..rate_limit import allow_websocket
from ..projects import require_project_role

router = APIRouter()
logger = logging.getLogger("aegis.main")


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
    try:
        while True:
            # Non-blocking poll for pubsub messages
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if message:
                data = json.loads(message['data'].decode('utf-8'))
                await websocket.send_json(data)
                if data.get("type") == "state" and data.get("state") in ("completed", "failed", "cancelled"):
                    break
            else:
                await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe(f"job_channel:{job_id}")
        pubsub.close()
