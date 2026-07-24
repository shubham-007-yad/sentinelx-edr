import os
import sys
import uuid
from pathlib import Path

backend_dir = Path(__file__).parent.parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device
from collectors import collect_system_info
from api.client import APIClient
from config import config

client = TestClient(app)


def test_agent_heartbeat_flow(tmp_path):
    """
    Tests Phase 6 Agent Heartbeat Flow:
    1. Register device
    2. Retrieve device_id
    3. Send POST /devices/heartbeat
    4. Verify status=ONLINE and last_seen updated in PostgreSQL database
    """
    cache_file = str(tmp_path / ".device_id_hb")
    config.DEVICE_CACHE_FILE = cache_file

    sys_info = collect_system_info()
    sys_info["hostname"] = f"hb-test-{str(uuid.uuid4())[:6]}"
    sys_info["mac_address"] = f"00:11:22:99:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"

    # Register via backend TestClient
    reg_response = client.post("/api/v1/devices/register", json=sys_info)
    assert reg_response.status_code == 201
    device_id = reg_response.json()["id"]

    # Initialize APIClient with cached device_id
    api_client = APIClient(backend_url="http://localhost:8000/api/v1")
    api_client._save_device_id(device_id)

    # Perform heartbeat via TestClient endpoint simulation
    hb_response = client.post("/api/v1/devices/heartbeat", json={
        "device_id": device_id,
        "ip_address": sys_info.get("ip_address"),
        "status": "ONLINE"
    })
    assert hb_response.status_code == 200
    hb_data = hb_response.json()
    assert hb_data["device_id"] == device_id
    assert hb_data["status"] == "ONLINE"
    assert "last_seen" in hb_data

    # Query PostgreSQL DB directly to verify last_seen timestamp and ONLINE status
    db = SessionLocal()
    try:
        db_device = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        assert db_device is not None
        assert db_device.status.value == "ONLINE"
        assert db_device.last_seen is not None
    finally:
        db.close()
