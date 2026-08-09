import pytest
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.process_audit_log import ProcessAuditLog, ProcessEventType
from app.services.process_service import log_process_audit_event, get_process_audit_logs
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_process_audit_log_service():
    db = SessionLocal()
    try:
        device = Device(
            hostname="audit-test-host",
            ip_address="192.168.1.250",
            mac_address="AA:BB:CC:DD:EE:99",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # Log PROCESS_STARTED
        log1 = log_process_audit_event(
            db=db,
            device_id=device.id,
            pid=1234,
            ppid=1,
            process_name="bash",
            event_type=ProcessEventType.PROCESS_STARTED,
            details="Shell started by user"
        )
        assert log1.id is not None

        # Log DETECTION_FOUND
        log2 = log_process_audit_event(
            db=db,
            device_id=device.id,
            pid=5678,
            ppid=1234,
            process_name="nc",
            event_type=ProcessEventType.DETECTION_FOUND,
            details="[LOLBinsRule] Netcat reverse shell detected"
        )
        assert log2.id is not None

        # Query process audit logs
        logs = get_process_audit_logs(db=db, device_id=device.id)
        assert len(logs) >= 2

        # Query by event_type
        det_logs = get_process_audit_logs(db=db, device_id=device.id, event_type=ProcessEventType.DETECTION_FOUND)
        assert len(det_logs) == 1
        assert det_logs[0].process_name == "nc"

    finally:
        db.close()


def test_process_audit_logs_api():
    db = SessionLocal()
    try:
        device = Device(
            hostname="audit-api-host",
            ip_address="192.168.1.251",
            mac_address="AA:BB:CC:DD:EE:98",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        log_process_audit_event(
            db=db,
            device_id=device.id,
            pid=8888,
            process_name="powershell.exe",
            event_type=ProcessEventType.RESPONSE_ACTION,
            details="Terminated process powershell.exe"
        )

        response = client.get(f"/api/v1/processes/audit-logs?device_id={device.id}")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert data[0]["process_name"] == "powershell.exe"
        assert data[0]["event_type"] == "RESPONSE_ACTION"

    finally:
        db.close()
