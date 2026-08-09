import logging
import asyncio
from typing import List, Dict, Any, Union, Optional
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages active WebSocket client connections for real-time dashboard updates and agent command channels.
    Supports tracking connections, handling disconnects, and broadcasting messages/alerts.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.agent_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, device_id: Optional[str] = None):
        """Accepts a new WebSocket connection and adds it to the active pool or agent connections."""
        await websocket.accept()
        self.active_connections.append(websocket)
        if device_id:
            self.agent_connections[str(device_id)] = websocket
            logger.info(f"Agent WebSocket client connected for device_id: {device_id}")
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket, device_id: Optional[str] = None):
        """Removes a WebSocket connection from the active pool and agent dict."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if device_id and str(device_id) in self.agent_connections:
            del self.agent_connections[str(device_id)]
        logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    async def send_command_to_device(self, device_id: str, message: Union[str, Dict[str, Any]]) -> bool:
        """Sends a command directly to a specific connected agent by device_id."""
        ws = self.agent_connections.get(str(device_id))
        if ws:
            try:
                if isinstance(message, dict):
                    await ws.send_json(message)
                else:
                    await ws.send_text(message)
                return True
            except Exception as e:
                logger.warning(f"Error sending command to device {device_id}: {e}")
                self.disconnect(ws, device_id=device_id)
                return False
        return False

    async def send_personal_message(self, message: Union[str, Dict[str, Any]], websocket: WebSocket):
        """Sends a message directly to a specific connected client."""
        try:
            if isinstance(message, dict):
                await websocket.send_json(message)
            else:
                await websocket.send_text(message)
        except Exception as e:
            logger.warning(f"Error sending message to client: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: Union[str, Dict[str, Any]]):
        """Broadcasts a JSON or text message to all currently connected clients."""
        disconnected_clients = []
        for connection in list(self.active_connections):
            try:
                if isinstance(message, dict):
                    await connection.send_json(message)
                else:
                    await connection.send_text(message)
            except Exception as e:
                logger.warning(f"Error broadcasting to client, removing connection: {e}")
                disconnected_clients.append(connection)

        for client in disconnected_clients:
            self.disconnect(client)

    async def broadcast_alert(self, alert_data: Dict[str, Any]):
        """Broadcasts a new threat alert event to all connected dashboard clients."""
        payload = {
            "event": "NEW_ALERT",
            "data": alert_data
        }
        await self.broadcast(payload)

    def broadcast_sync(self, message: Union[str, Dict[str, Any]]):
        """Synchronous helper method to trigger broadcasts from sync contexts."""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                loop.create_task(self.broadcast(message))
            else:
                loop.run_until_complete(self.broadcast(message))
        except RuntimeError:
            try:
                asyncio.run(self.broadcast(message))
            except Exception as e:
                logger.error(f"Failed to run broadcast in async loop: {e}")

    def broadcast_alert_sync(self, alert_data: Dict[str, Any]):
        """Synchronous helper to broadcast an alert payload."""
        payload = {
            "event": "NEW_ALERT",
            "data": alert_data
        }
        self.broadcast_sync(payload)


websocket_manager = ConnectionManager()
