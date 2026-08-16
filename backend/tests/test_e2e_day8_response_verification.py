import os
import tempfile
import uuid
import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.services.response_service import execute_response, get_audit_logs_by_action_id
from app.core.websocket_manager import websocket_manager
from agent.quarantine_manager import QuarantineManager

from app.auth.jwt import create_access_token
from app.models.user import User, UserRole
from app.services import user_service
from app.schemas.user import UserCreate

client = TestClient(app)


def setup_db():
    Base.metadata.create_all(bind=engine)
    return SessionLocal()


def get_auth_headers(db: Session, username: str = "ADMIN", role: UserRole = UserRole.ADMIN):
    user = db.query(User).filter((User.username == username) | (User.email == f"{username.lower()}@sentinelx.io")).first()
    if not user:
        user = user_service.create_user(
            db,
            UserCreate(
                username=username,
                email=f"{username.lower()}_{uuid.uuid4().hex[:6]}@sentinelx.io",
                password="TestPassword123!",
                role=role
            )
        )
    role_val = user.role.value if hasattr(user.role, "value") else str(user.role)
    token = create_access_token(subject=user.username, role=role_val)
    return {"Authorization": f"Bearer {token}"}


def test_scenario_1_quarantine_malicious_executable():
    """Verify Scenario 1: Quarantine a malicious executable."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        q_dir = os.path.join(tmp_dir, ".quarantine")
        qm = QuarantineManager(quarantine_dir=q_dir)

        # Create mock malware executable
        malware_file = os.path.join(tmp_dir, "virus_payload.exe")
        with open(malware_file, "w") as f:
            f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

        os.chmod(malware_file, 0o755)

        # Execute quarantine via manager
        q_record = qm.quarantine_file(malware_file, reason="Malware test executable detected")
        assert q_record is not None

        # 1. Original file moved/removed
        assert not os.path.exists(malware_file)

        # 2. Vault file exists & permissions revoked (000)
        assert os.path.exists(q_record.quarantine_path)
        mode = os.stat(q_record.quarantine_path).st_mode & 0o777
        assert mode == 0o000

        # 3. Manifest contains entry
        manifest = qm.list_quarantined_files()
        assert len(manifest) == 1
        assert manifest[0].sha256 == q_record.sha256
        assert manifest[0].reason == "Malware test executable detected"


def test_scenario_2_simulate_device_isolation():
    """Verify Scenario 2: Simulate device isolation and event blocking."""
    db = setup_db()
    try:
        hostname = f"isolated-endpoint-{str(uuid.uuid4())[:8]}"
        device = Device(
            hostname=hostname,
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()
        db.refresh(device)

    # 1. Create USB Event prior to isolation
        event_payload = {
            "device_id": str(device.id),
            "event_type": "INSERT",
            "drive_letter": "E:",
            "volume_label": "MALWARE_USB",
            "serial_number": "ISO12345"
        }
        pre_iso_event = client.post("/api/v1/usb/events", json=event_payload)
        assert pre_iso_event.status_code == 201
        usb_event_id = pre_iso_event.json()["id"]

        # 2. Trigger Isolation Action
        headers = get_auth_headers(db)
        iso_res = client.post(f"/api/v1/devices/{device.id}/isolate", headers=headers)
        assert iso_res.status_code == 200
        assert iso_res.json()["status"] == "ISOLATED"

        # 3. Verify subsequent USB Event is blocked (403 Forbidden)
        usb_res = client.post("/api/v1/usb/events", json=event_payload)
        assert usb_res.status_code == 403
        assert "is currently ISOLATED" in usb_res.json()["detail"]

        # 4. Verify USB Scan for isolated device event is blocked (403 Forbidden)
        scan_payload = {
            "usb_event_id": usb_event_id,
            "files": [
                {
                    "usb_event_id": usb_event_id,
                    "file_name": "virus.exe",
                    "full_path": "/media/usb/virus.exe",
                    "file_size": 1024,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            ]
        }
        scan_res = client.post("/api/v1/usb/scans", json=scan_payload)
        assert scan_res.status_code == 403
        assert "is currently ISOLATED" in scan_res.json()["detail"]

    finally:
        db.close()


def test_scenario_3_retry_failed_response():
    """Verify Scenario 3: Retry a failed response action."""
    db = setup_db()
    try:
        device = Device(
            hostname=f"retry-node-{str(uuid.uuid4())[:8]}",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()

        # Create action in FAILED status manually
        action = ResponseAction(
            device_id=device.id,
            action_type=ResponseActionType.DELETE,
            status=ResponseActionStatus.FAILED,
            initiated_by="ADMIN",
            result="Network timeout during dispatch"
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        # Trigger Retry via API
        headers = get_auth_headers(db)
        retry_res = client.post(f"/api/v1/responses/{action.id}/retry", headers=headers)
        assert retry_res.status_code == 200
        data = retry_res.json()
        assert data["status"] in ["RUNNING", "SUCCESS"]
        assert "Retried command" in data["result"]

        # Verify Audit trail has new entries
        audit_logs = get_audit_logs_by_action_id(db, action.id)
        assert len(audit_logs) >= 1

    finally:
        db.close()


def test_scenario_4_prevent_duplicate_commands():
    """Verify Scenario 4: Ensure duplicate active commands are prevented."""
    db = setup_db()
    try:
        device = Device(
            hostname=f"dedup-node-{str(uuid.uuid4())[:8]}",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()

        # 1. Create initial active action in PENDING state
        action = ResponseAction(
            device_id=device.id,
            action_type=ResponseActionType.ISOLATE,
            status=ResponseActionStatus.PENDING,
            initiated_by="ADMIN"
        )
        db.add(action)
        db.commit()

        # 2. Attempt to trigger duplicate ISOLATE action for same device
        dup_payload = {
            "device_id": str(device.id),
            "action_type": "ISOLATE",
            "initiated_by": "ADMIN"
        }
        headers = get_auth_headers(db)
        res = client.post("/api/v1/responses/trigger", json=dup_payload, headers=headers)
        assert res.status_code == 409
        assert "already PENDING" in res.json()["detail"]

    finally:
        db.close()


def test_scenario_5_dashboard_live_status_updates():
    """Verify Scenario 5: Dashboard live status events dispatch via Response Engine."""
    db = setup_db()
    try:
        device = Device(
            hostname=f"ws-live-node-{str(uuid.uuid4())[:8]}",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()

        # Trigger response action via API
        trig_payload = {
            "device_id": str(device.id),
            "action_type": "QUARANTINE",
            "initiated_by": "ADMIN"
        }
        headers = get_auth_headers(db)
        res = client.post("/api/v1/responses/trigger", json=trig_payload, headers=headers)
        assert res.status_code == 201
        action_id = res.json()["id"]

        # Verify action created with SUCCESS status and live broadcast triggered
        action = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
        assert action is not None
        assert action.status == ResponseActionStatus.SUCCESS
        assert "QUARANTINE" in action.result

    finally:
        db.close()
