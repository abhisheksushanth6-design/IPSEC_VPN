"""WebSocket route foundation.

`/ws/events` accepts connections and acknowledges them. It deliberately emits
no packet, anomaly or security events — those arrive with later layers.
"""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import get_settings
from app.websocket.manager import connection_manager

router = APIRouter()


@router.websocket("/ws/events")
async def events_socket(websocket: WebSocket) -> None:
    """Maintain an event channel that currently carries no security events."""
    await connection_manager.connect(websocket)
    try:
        await websocket.send_json(
            {
                "type": "connection.established",
                "project": get_settings().project_name,
                "message": "Event stream foundation ready. No event sources are active.",
            }
        )
        while True:
            # Echo-free keepalive: read and discard client frames until close.
            await websocket.receive_text()
    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)
