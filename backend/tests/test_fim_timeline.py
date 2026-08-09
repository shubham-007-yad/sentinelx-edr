import pytest
from datetime import datetime, timezone
from uuid import uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.schemas.file_integrity import FileIntegrityRecordCreate, FileChangeEventRequest, FIMResponseActionRequest
from app.services import file_integrity_service


@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def timeline_test_device(db_session):
    device = Device(
        hostname="fim-timeline-node",
        ip_address="192.168.1.120",
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_fim_chronological_timeline_pipeline(db_session, client, timeline_test_device):
    file_path = "/home/user/Downloads/setup.exe"

    # Step 1: 12:00 - File Created
    rec = FileIntegrityRecordCreate(
        file_path=file_path,
        file_name="setup.exe",
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        size=1024,
        owner="user",
        is_executable=True
    )
    file_integrity_service.upsert_file_integrity_record(
        db=db_session,
        device_id=timeline_test_device.id,
        record_in=rec
    )

    # Step 2: 12:01 - SHA Changed
    change_evt = FileChangeEventRequest(
        event_type="MODIFIED",
        file_path=file_path,
        file_name="setup.exe",
        sha256="2222222222222222222222222222222222222222222222222222222222222222",
        size=2048,
        is_executable=True,
        owner="user"
    )
    file_integrity_service.verify_file_integrity_change(
        db=db_session,
        device_id=timeline_test_device.id,
        event=change_evt
    )

    # Step 3: 12:01 - Threat & Alert Generated
    threat = Threat(
        threat_type=ThreatType.FIM_EXECUTABLE_IN_DOWNLOADS,
        severity=ThreatSeverity.HIGH,
        rule_name="FIM Executable Dropped in Downloads",
        description=f"Executable setup.exe dropped in Downloads: {file_path}",
        status=ThreatStatus.NEW
    )
    db_session.add(threat)
    db_session.commit()
    db_session.refresh(threat)

    alert = Alert(
        threat_id=threat.id,
        device_id=timeline_test_device.id,
        title="High Severity Alert: Executable Dropped in Downloads",
        message=f"Executable setup.exe dropped in Downloads directory: {file_path}",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.UNREAD
    )
    db_session.add(alert)
    db_session.commit()

    # Step 4: 12:02 - Quarantined Response Action
    file_integrity_service.execute_fim_response_action(
        db=db_session,
        device_id=timeline_test_device.id,
        payload=FIMResponseActionRequest(file_path=file_path, action_type="QUARANTINE")
    )

    # Step 5: Query Timeline API Endpoint
    res = client.get(f"/api/v1/fim/timeline/{timeline_test_device.id}?file_path={file_path}")
    assert res.status_code == 200
    data = res.json()

    assert data["file_path"] == file_path
    assert data["file_name"] == "setup.exe"
    timeline = data["timeline"]

    # Verify chronological sequence (Step 1: Created, Step 2: SHA Changed, Step 3: Alert, Step 4: Quarantined)
    assert len(timeline) >= 4
    events = [item["event_type"] for item in timeline]
    assert "FILE_CREATED" in events
    assert "SHA_CHANGED" in events
    assert "ALERT_GENERATED" in events
    assert "RESPONSE_EXECUTED" in events

    # Verify 1-indexed step numbering
    for i, item in enumerate(timeline, start=1):
        assert item["step"] == i
