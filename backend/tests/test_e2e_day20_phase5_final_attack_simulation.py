import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.user import User, UserRole
from app.models.device import Device, DeviceStatus, OSType
from app.models.response_audit_log import ResponseAuditLog
from app.auth.jwt import create_access_token


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def admin_headers(setup_db: Session):
    db = setup_db
    user = db.query(User).filter(User.username == "admin_phase5_sim").first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            username="admin_phase5_sim",
            email="admin_p5@sentinelx.io",
            password_hash="pass_hash",
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(user)
        db.commit()

    user.role = UserRole.ADMIN
    db.commit()
    db.refresh(user)

    token = create_access_token(subject=user.username, role="ADMIN")
    return {"Authorization": f"Bearer {token}"}


def test_simulation_1_double_extension_usb_attack(setup_db: Session, admin_headers: dict):
    """
    Simulation 1: Harmless Double Extension USB Payload Simulation
    invoice.pdf.exe ➔ Double Extension Rule ➔ CRITICAL Threat ➔ Alert ➔ Investigation Case ➔ File Quarantine ➔ Audit Trail
    """
    db = setup_db
    client = TestClient(app)
    device_id = str(uuid.uuid4())
    shared_corr_id = str(uuid.uuid4())

    # 1. Device Registration
    reg_res = client.post("/api/v1/devices/register", json={
        "hostname": "FINANCE-WORKSTATION-01",
        "ip_address": "10.0.4.15",
        "mac_address": "AA:BB:CC:11:22:33",
        "os_type": "WINDOWS",
        "os_version": "Windows 11 23H2",
        "agent_version": "v1.0.0"
    })
    assert reg_res.status_code == 201
    registered_dev_id = reg_res.json()["id"]

    # 2. USB Insertion Event
    usb_res = client.post("/api/v1/usb/events", json={
        "device_id": registered_dev_id,
        "event_type": "INSERT",
        "drive_letter": "E:",
        "volume_label": "DOCUMENTS_USB",
        "filesystem": "FAT32",
        "total_size": 16000000000,
        "free_space": 10000000000,
        "serial_number": "SIM-USB-9901"
    })
    assert usb_res.status_code == 201
    usb_evt_id = usb_res.json()["id"]

    # 3. Double Extension File Scan Upload (invoice.pdf.exe)
    scan_res = client.post("/api/v1/usb/scans", json=[{
        "usb_event_id": usb_evt_id,
        "file_name": "q4_invoice_receipt.pdf.exe",
        "full_path": "E:\\q4_invoice_receipt.pdf.exe",
        "extension": ".exe",
        "file_size": 1048576,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "is_hidden": True
    }])
    assert scan_res.status_code == 201

    # 4. Threat & Alert Listing Verification
    threats_res = client.get(f"/api/v1/threats?usb_event_id={usb_evt_id}", headers=admin_headers)
    assert threats_res.status_code == 200
    threats = threats_res.json()
    assert len(threats) >= 1
    assert threats[0]["severity"] in ["HIGH", "CRITICAL"]

    alerts_res = client.get(f"/api/v1/alerts?device_id={registered_dev_id}", headers=admin_headers)
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]

    # 5. Case Investigation Creation
    case_res = client.post("/api/v1/investigation/cases", json={
        "title": "Double Extension Trojan Outbreak Simulation",
        "description": "Simulated phishing attack via invoice.pdf.exe",
        "severity": "CRITICAL",
        "correlation_id": shared_corr_id,
        "linked_alert_ids": [alert_id]
    }, headers=admin_headers)
    assert case_res.status_code == 201

    # 6. File Quarantine Response Execution
    resp_res = client.post("/api/v1/responses/trigger", json={
        "device_id": registered_dev_id,
        "action_type": "QUARANTINE",
        "alert_id": alert_id,
        "initiated_by": "admin_phase5_sim",
        "parameters": {"file_path": "E:\\q4_invoice_receipt.pdf.exe"}
    }, headers=admin_headers)
    assert resp_res.status_code == 201
    action_id = resp_res.json()["id"]

    # 7. Audit Log Trail Verification
    audit_logs = db.query(ResponseAuditLog).filter(ResponseAuditLog.action_id == uuid.UUID(action_id)).all()
    assert len(audit_logs) >= 1


def test_simulation_2_suspicious_process_powershell_attack(setup_db: Session, admin_headers: dict):
    """
    Simulation 2: Suspicious Process Execution Attack Simulation
    powershell.exe ➔ Encoded Command Line ➔ Behavioral Detection ➔ HIGH/CRITICAL Alert ➔ Process Termination
    """
    client = TestClient(app)

    # 1. Device Registration
    reg_res = client.post("/api/v1/devices/register", json={
        "hostname": "EXEC-LAPTOP-02",
        "ip_address": "10.0.4.88",
        "mac_address": "BB:CC:DD:22:33:44",
        "os_type": "WINDOWS",
        "os_version": "Windows 11 Pro",
        "agent_version": "v1.0.0"
    })
    assert reg_res.status_code == 201
    device_id = reg_res.json()["id"]
    corr_id = str(uuid.uuid4())

    # 2. Ingest Suspicious PowerShell Process Telemetry
    process_evt = {
        "event_id": str(uuid.uuid4()),
        "device_id": device_id,
        "category": "PROCESS",
        "event_type": "PROCESS_STARTED",
        "source": "ProcessMonitor",
        "correlation_id": corr_id,
        "payload": {
            "process_id": 4912,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgA...",
            "parent_process_name": "cmd.exe",
            "user": "NT AUTHORITY\\SYSTEM"
        }
    }

    telemetry_res = client.post("/api/v1/telemetry/ingest", json={
        "device_id": device_id,
        "events": [process_evt]
    })
    assert telemetry_res.status_code == 201

    # 3. Process Response Action Trigger (TERMINATE_PROCESS)
    resp_res = client.post("/api/v1/responses/trigger", json={
        "device_id": device_id,
        "action_type": "TERMINATE_PROCESS",
        "initiated_by": "admin_phase5_sim",
        "parameters": {"process_id": 4912, "process_name": "powershell.exe"}
    }, headers=admin_headers)
    assert resp_res.status_code == 201
    assert resp_res.json()["action_type"] == "TERMINATE_PROCESS"


def test_simulation_3_ransomware_behavioral_attack(setup_db: Session, admin_headers: dict):
    """
    Simulation 3: Ransomware Behavioral Attack Simulation
    Mass File Modifications (.locked) ➔ Behavioral Correlation ➔ Ransomware Detection ➔ CRITICAL Outbreak ➔ Host Network Isolation
    """
    client = TestClient(app)

    # 1. Device Registration
    reg_res = client.post("/api/v1/devices/register", json={
        "hostname": "DB-SERVER-PRIMARY",
        "ip_address": "10.0.1.100",
        "mac_address": "CC:DD:EE:33:44:55",
        "os_type": "WINDOWS",
        "os_version": "Windows Server 2022",
        "agent_version": "v1.0.0"
    })
    assert reg_res.status_code == 201
    device_id = reg_res.json()["id"]
    corr_id = str(uuid.uuid4())

    # 2. Ingest Mass Ransomware Encryption Behavioral Telemetry
    ransomware_evt = {
        "event_id": str(uuid.uuid4()),
        "device_id": device_id,
        "category": "RANSOMWARE",
        "event_type": "MASS_FILE_ENCRYPTION",
        "source": "RansomwareBehaviorEngine",
        "correlation_id": corr_id,
        "payload": {
            "files_encrypted_count": 450,
            "target_directory": "C:\\Users\\Administrator\\Documents",
            "encrypted_extension": ".locked",
            "average_file_entropy": 7.98,
            "ransom_note_detected": True,
            "ransom_note_name": "READ_ME_NOW.txt"
        }
    }

    telemetry_res = client.post("/api/v1/telemetry/ingest", json={
        "device_id": device_id,
        "events": [ransomware_evt]
    })
    assert telemetry_res.status_code == 201

    # 3. Emergency Response Action Trigger (ISOLATE)
    resp_res = client.post("/api/v1/responses/trigger", json={
        "device_id": device_id,
        "action_type": "ISOLATE",
        "initiated_by": "admin_phase5_sim",
        "parameters": {"isolation_level": "STRICT_NETWORK_BLOCK", "reason": "Active Ransomware Outbreak Mitigated"}
    }, headers=admin_headers)
    assert resp_res.status_code == 201
    assert resp_res.json()["action_type"] == "ISOLATE"
