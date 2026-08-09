import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.core.websocket_manager import ConnectionManager, websocket_manager


def test_websocket_manager_connect_disconnect_broadcast():
    async def _test():
        manager = ConnectionManager()
        
        # Mock WebSockets
        class DummyWebSocket:
            def __init__(self):
                self.accepted = False
                self.sent_messages = []

            async def accept(self):
                self.accepted = True

            async def send_json(self, data):
                self.sent_messages.append(data)

            async def send_text(self, text):
                self.sent_messages.append(text)

        client1 = DummyWebSocket()
        client2 = DummyWebSocket()

        # 1. Connect
        await manager.connect(client1)
        await manager.connect(client2)
        assert len(manager.active_connections) == 2
        assert client1.accepted is True
        assert client2.accepted is True

        # 2. Broadcast JSON
        test_msg = {"event": "TEST", "detail": "Hello Clients"}
        await manager.broadcast(test_msg)
        assert len(client1.sent_messages) == 1
        assert client1.sent_messages[0] == test_msg
        assert len(client2.sent_messages) == 1
        assert client2.sent_messages[0] == test_msg

        # 3. Disconnect client 1
        manager.disconnect(client1)
        assert len(manager.active_connections) == 1

        # 4. Broadcast Alert
        alert_payload = {"id": "test-uuid", "title": "Critical Threat"}
        await manager.broadcast_alert(alert_payload)
        assert len(client2.sent_messages) == 2
        assert client2.sent_messages[1] == {"event": "NEW_ALERT", "data": alert_payload}

    asyncio.run(_test())


def test_fastapi_websocket_endpoint():
    from app.auth.jwt import create_access_token
    token = create_access_token(subject="ws_test_user", role="ADMIN")
    client = TestClient(app)
    with client.websocket_connect(f"/ws/alerts?token={token}") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"
