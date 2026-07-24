import os
import sys
import uuid
from pathlib import Path
import pytest

# Add backend to Python path for direct DB and FastAPI TestClient inspection
backend_dir = Path(__file__).parent.parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus
from collectors import collect_system_info, get_system_info_json
from api.client import APIClient
from config import config

client = TestClient(app)


def test_day3_full_e2e_workflow(tmp_path):
    """
    End-to-End Integration Test for Day 3:
    1. Run Agent System Info Collector
    2. Register Device with Backend
    3. Verify Device Saved in PostgreSQL
    4. Send Heartbeat from Agent
    5. Verify Backend Updates last_seen
    6. Verify GET /devices shows online device
    """
    # ----------------------------------------------------
    # Step 1: Run Agent & Collect System Info
    # ----------------------------------------------------
    cache_file = str(tmp_path / ".device_id_e2e")
    config.DEVICE_CACHE_FILE = cache_file

    sys_info = collect_system_info()
    unique_str = str(uuid.uuid4())[:6]
    test_hostname = f"e2e-node-{unique_str}"
    test_mac = f"02:00:00:11:{unique_str[:2]}:{unique_str[2:4]}"
    
    sys_info["hostname"] = test_hostname
    sys_info["mac_address"] = test_mac
    sys_info["mac"] = test_mac

    json_payload = get_system_info_json()
    assert json_payload is not None
    assert sys_info["hostname"] == test_hostname

    # ----------------------------------------------------
    # Step 2: Register Device (POST /devices/register)
    # ----------------------------------------------------
    reg_response = client.post("/api/v1/devices/register", json=sys_info)
    assert reg_response.status_code == 201
    reg_data = reg_response.json()
    assert "id" in reg_data
    device_id = reg_data["id"]

    # Save device_id locally in agent cache
    api_client = APIClient(backend_url="http://localhost:8000/api/v1")
    api_client._save_device_id(device_id)

    assert os.path.exists(cache_file)
    with open(cache_file, "r") as f:
        assert f.read().strip() == device_id

    # ----------------------------------------------------
    # Step 3: Verify Device Saved in PostgreSQL Database
    # ----------------------------------------------------
    db = SessionLocal()
    try:
        db_device = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        assert db_device is not None
        assert db_device.hostname == test_hostname
        assert db_device.mac_address == test_mac
        assert db_device.status == DeviceStatus.ONLINE
        initial_last_seen = db_device.last_seen
    finally:
        db.close()

    # ----------------------------------------------------
    # Step 4 & 5: Heartbeat Sent & Backend Updates last_seen
    # ----------------------------------------------------
    hb_response = client.post("/api/v1/devices/heartbeat", json={
        "device_id": device_id,
        "ip_address": sys_info["ip_address"],
        "status": "ONLINE"
    })
    assert hb_response.status_code == 200
    hb_data = hb_response.json()
    assert hb_data["device_id"] == device_id
    assert hb_data["status"] == "ONLINE"
    assert "last_seen" in hb_data

    # Re-verify PostgreSQL DB for last_seen timestamp update
    db = SessionLocal()
    try:
        db_device_after = db.query(Device).filter(Device.id == uuid.UUID(device_id)).first()
        assert db_device_after.last_seen is not None
        assert db_device_after.status == DeviceStatus.ONLINE
    finally:
        db.close()

    # ----------------------------------------------------
    # Step 6: GET /devices Shows Online Device
    # ----------------------------------------------------
    list_response = client.get("/api/v1/devices")
    assert list_response.status_code == 200
    devices_list = list_response.json()
    
    matching_devices = [d for d in devices_list if d["id"] == device_id]
    assert len(matching_devices) == 1
    found_device = matching_devices[0]
    assert found_device["hostname"] == test_hostname
    assert found_device["status"] == "ONLINE"

    # GET /devices/{id} Verification
    detail_response = client.get(f"/api/v1/devices/{device_id}")
    assert detail_response.status_code == 200
    detail_data = detail_response.json()
    assert detail_data["id"] == device_id
    assert detail_data["hostname"] == test_hostname
    assert detail_data["status"] == "ONLINE"
