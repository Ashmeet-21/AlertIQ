"""
WebSocket connection manager.

- Dashboard clients connect to /ws/alerts.
- When a background pipeline thread finishes processing an alert, it calls
  broadcast_from_thread(), which safely schedules a coroutine on the main
  event loop via asyncio.run_coroutine_threadsafe().
- The dashboard receives a small JSON event and refreshes its alert list.
"""
import asyncio
import logging
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once at startup with the running event loop."""
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.append(ws)
        logger.info(f"[ws] client connected — {len(self.connections)} active")

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.connections:
            self.connections.remove(ws)
        logger.info(f"[ws] client disconnected — {len(self.connections)} active")

    async def broadcast(self, data: dict) -> None:
        """Send a JSON message to every connected dashboard."""
        dead: list[WebSocket] = []
        for ws in self.connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def broadcast_from_thread(self, data: dict) -> None:
        """
        Thread-safe broadcast.
        Safe to call from FastAPI BackgroundTasks (which run in a thread pool).
        """
        if self._loop is not None and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(data), self._loop)


# Singleton — imported by routes_ws.py and routes_ingest.py
ws_manager = ConnectionManager()
