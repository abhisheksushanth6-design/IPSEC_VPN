"""WebSocket foundation at /ws/events."""

from __future__ import annotations


def test_events_socket_accepts_and_announces(client) -> None:
    with client.websocket_connect("/ws/events") as socket:
        message = socket.receive_json()
    assert message["type"] == "connection.established"
    assert "No event sources are active" in message["message"]
