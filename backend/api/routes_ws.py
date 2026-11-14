"""
GET /ws/alerts?token=<jwt>: pushes {"type", "alert_id", ...} whenever an alert changes.
The token goes in the query string because browsers can't set headers on WebSockets.
"""
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError
from backend.core.auth import decode_token
from backend.core.ws_manager import ws_manager
from backend.database import open_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket, token: str | None = None):
    if not token:
        await ws.close(code=1008, reason="missing token")
        return
    try:
        payload = decode_token(token)
    except JWTError:
        await ws.close(code=1008, reason="invalid or expired token")
        return
    # Short-lived connection: a Depends(get_db) here would hold a DB connection open
    # for as long as the dashboard tab stays open.
    with open_db() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = %s", (payload.get("sub"),)).fetchone()
    if not row:
        await ws.close(code=1008, reason="user not found")
        return

    await ws_manager.connect(ws)
    try:
        # Keep connection alive — client sends a ping every 30s; we just discard it
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception as exc:
        logger.warning(f"[ws] unexpected disconnect: {exc}")
        ws_manager.disconnect(ws)
