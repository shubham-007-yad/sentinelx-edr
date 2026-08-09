import pytest
from datetime import datetime, timezone
from uuid import uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.schemas.file_integrity import FileIntegrityRecordCreate, FileChangeEventRequest
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
def diff_test_device(db_session):
    device = Device(
        hostname="fim-diff-host",
        ip_address="192.168.1.55",
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_verify_file_change_integrity(db_session, client, diff_test_device):
    file_path = "/etc/nginx/nginx.conf"
    baseline_hash = "1111111111111111111111111111111111111111111111111111111111111111"

    # Step 1: Create baseline record
    rec_in = FileIntegrityRecordCreate(
        file_path=file_path,
        file_name="nginx.conf",
        sha256=baseline_hash,
        size=2048,
        last_modified=datetime.now(timezone.utc),
        owner="root",
        is_executable=False
    )
    file_integrity_service.upsert_file_integrity_record(
        db=db_session,
        device_id=diff_test_device.id,
        record_in=rec_in
    )

    # Step 2: Simulate file modification (New hash & size)
    new_hash = "9999999999999999999999999999999999999999999999999999999999999999"
    change_event = {
        "event_type": "MODIFIED",
        "file_path": file_path,
        "file_name": "nginx.conf",
        "sha256": new_hash,
        "size": 2500,
        "is_executable": False,
        "owner": "root"
    }

    res = client.post(f"/api/v1/fim/verify/{diff_test_device.id}", json=change_event)
    assert res.status_code == 200
    data = res.json()

    assert data["is_changed"] is True
    assert data["status"] == "CHANGED"
    assert "sha256_mismatch" in data["changes_detected"]
    assert "size_mismatch" in data["changes_detected"]
    assert data["baseline_sha256"] == baseline_hash
    assert data["current_sha256"] == new_hash

    # Step 3: Verify DB baseline updated
    updated_records = file_integrity_service.get_file_integrity_records(
        db=db_session,
        device_id=diff_test_device.id,
        file_path=file_path
    )
    assert len(updated_records) == 1
    assert updated_records[0].sha256 == new_hash
    assert updated_records[0].size == 2500
