"""
WebSocket endpoint — GET /ws/alerts

Dashboard clients connect here to receive real-time alert update events.
Token is passed as a query parameter because the WebSocket spec doesn't
support custom headers from the browser.

Each message sent to connected clients looks like:
{
  "type": "alert_updated",
  "alert_id": "...",
  "status": "triage" | "escalated" | "suppressed",
  "queue": "P1" | "P2" | "P3" | "P4",
  "score": 85
}
"""
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.core.ws_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
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
