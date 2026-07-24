import os
import sys
import uuid
from pathlib import Path

# Add backend directory to sys.path for database and app imports
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


def test_agent_registration_flow(tmp_path):
    """
    Tests the complete Phase 5 Agent Registration Flow:
    1. Collect system info
    2. Call registration endpoint
    3. Receive device_id
    4. Save device_id locally
    5. Verify record in PostgreSQL database
    """
    # 1. Setup temporary cache file
    cache_file = str(tmp_path / ".device_id_phase5")
    config.DEVICE_CACHE_FILE = cache_file

    # 2. Collect system info payload
    sys_info = collect_system_info()
    sys_info["hostname"] = f"phase5-host-{str(uuid.uuid4())[:6]}"
    sys_info["mac_address"] = f"00:11:22:55:{str(uuid.uuid4())[:2]}:{str(uuid.uuid4())[:2]}"

    # 3. Simulate POST /devices/register request to backend
    response = client.post("/api/v1/devices/register", json=sys_info)
    assert response.status_code == 201
    res_data = response.json()
    assert "id" in res_data
    device_id = res_data["id"]

    # 4. Save device_id locally using APIClient helper
    api_client = APIClient(backend_url="http://localhost:8000/api/v1")
    api_client._save_device_id(device_id)

    # 5. Verify local file saving
    assert os.path.exists(cache_file)
    with open(cache_file, "r") as f:
        saved_id = f.read().strip()
    assert saved_id == device_id
    assert api_client.device_id == device_id

    # 6. Verify device record in PostgreSQL database
    db = SessionLocal()
    try:
        db_device = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        assert db_device is not None
        assert db_device.hostname == sys_info["hostname"]
        assert db_device.status.value == "ONLINE"
    finally:
        db.close()
