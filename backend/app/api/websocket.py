from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from app.core.websocket_manager import websocket_manager
from app.auth.jwt import decode_access_token

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/alerts")
async def websocket_alerts_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="JWT Bearer Access Token for real-time alert stream")
):
    """
    WebSocket endpoint for real-time threat alert streaming to dashboard clients.
    Enforces JWT authentication token validation upon connection handshake.
    """
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or missing authentication token.")
        return

    await websocket_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
    except Exception:
        websocket_manager.disconnect(websocket)


@router.websocket("/ws/agent/{device_id}")
async def websocket_agent_endpoint(
    websocket: WebSocket,
    device_id: str,
    token: str = Query(None, description="Optional JWT or agent authentication token")
):
    """
    WebSocket endpoint for EDR Endpoint Agent real-time command channel.
    """
    await websocket_manager.connect(websocket, device_id=device_id)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket, device_id=device_id)
    except Exception:
        websocket_manager.disconnect(websocket, device_id=device_id)
