"""Connection manager for future real-time event broadcasting.

The manager tracks connected clients and can fan out messages. No events are
produced at this stage — publishing is wired up by later layers.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Tracks active WebSocket clients."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)
        logger.info("WebSocket connected (%d active)", self.connection_count)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)
        logger.info("WebSocket disconnected (%d active)", self.connection_count)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Send a message to every connected client, dropping dead sockets."""
        stale: list[WebSocket] = []
        for connection in self._connections:
            try:
                await connection.send_json(message)
            except Exception:  # noqa: BLE001 - a dead socket must not stop the fan-out
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)


connection_manager = ConnectionManager()
