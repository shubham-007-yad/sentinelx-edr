import pytest
from uuid import uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.schemas.file_integrity import FileIntegrityRecordCreate, FIMResponseActionRequest
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
def response_test_device(db_session):
    device = Device(
        hostname="fim-resp-host",
        ip_address="192.168.1.110",
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_fim_response_actions_execution(db_session, client, response_test_device):
    file_path = "/etc/hosts"

    # Seed baseline
    rec = FileIntegrityRecordCreate(
        file_path=file_path,
        file_name="hosts",
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        size=300,
        owner="root",
        is_executable=False
    )
    file_integrity_service.upsert_file_integrity_record(
        db=db_session,
        device_id=response_test_device.id,
        record_in=rec
    )

    # 1. Test RESTORE_BASELINE
    res1 = client.post(f"/api/v1/fim/respond/{response_test_device.id}", json={
        "file_path": file_path,
        "action_type": "RESTORE_BASELINE"
    })
    assert res1.status_code == 200
    assert res1.json()["status"] == "SUCCESS"
    assert "restored" in res1.json()["message"].lower()

    # 2. Test QUARANTINE
    res2 = client.post(f"/api/v1/fim/respond/{response_test_device.id}", json={
        "file_path": file_path,
        "action_type": "QUARANTINE"
    })
    assert res2.status_code == 200
    assert res2.json()["status"] == "SUCCESS"
    assert "quarantine" in res2.json()["message"].lower()

    # 3. Test IGNORE_CHANGE
    res3 = client.post(f"/api/v1/fim/respond/{response_test_device.id}", json={
        "file_path": file_path,
        "action_type": "IGNORE_CHANGE"
    })
    assert res3.status_code == 200
    assert res3.json()["status"] == "SUCCESS"

    # 4. Test ADD_ALLOWLIST
    res4 = client.post(f"/api/v1/fim/respond/{response_test_device.id}", json={
        "file_path": file_path,
        "action_type": "ADD_ALLOWLIST"
    })
    assert res4.status_code == 200
    assert res4.json()["status"] == "SUCCESS"

    # 5. Test RECALCULATE_BASELINE
    new_sha = "8888888888888888888888888888888888888888888888888888888888888888"
    res5 = client.post(f"/api/v1/fim/respond/{response_test_device.id}", json={
        "file_path": file_path,
        "action_type": "RECALCULATE_BASELINE",
        "new_sha256": new_sha,
        "new_size": 450
    })
    assert res5.status_code == 200
    assert res5.json()["status"] == "SUCCESS"

    # Verify baseline updated in DB
    updated = file_integrity_service.get_file_integrity_records(db=db_session, device_id=response_test_device.id, file_path=file_path)
    assert updated[0].sha256 == new_sha
    assert updated[0].size == 450
