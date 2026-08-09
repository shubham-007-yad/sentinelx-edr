import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.schemas.file_integrity import (
    FileIntegrityRecordCreate, FileChangeEventRequest, FIMResponseActionRequest
)
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
def phase8_device(db_session):
    device = Device(
        hostname="fim-phase8-validator",
        ip_address="192.168.1.200",
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_phase8_complete_fim_validation_lifecycle(db_session, client, phase8_device):
    dev_id = phase8_device.id

    # 1. File Creation / Baseline
    rec = FileIntegrityRecordCreate(
        file_path="/home/user/Downloads/setup.exe",
        file_name="setup.exe",
        sha256="1111111111111111111111111111111111111111111111111111111111111111",
        size=1024,
        owner="user",
        is_executable=True
    )
    res_b = client.post(f"/api/v1/fim/baseline/{dev_id}", json={"records": [rec.model_dump(mode='json')]})
    assert res_b.status_code == 201

    # 2. File Modification & SHA-256 Change
    mod_evt = FileChangeEventRequest(
        event_type="MODIFIED",
        file_path="/home/user/Downloads/setup.exe",
        file_name="setup.exe",
        sha256="2222222222222222222222222222222222222222222222222222222222222222",
        size=2048,
        is_executable=True
    )
    res_m = client.post(f"/api/v1/fim/verify/{dev_id}", json=mod_evt.model_dump(mode='json'))
    assert res_m.status_code == 200
    assert res_m.json()["is_changed"] is True
    assert "sha256_mismatch" in res_m.json()["changes_detected"]

    # 3. Double Extension Masquerade Event
    de_evt = FileChangeEventRequest(
        event_type="CREATED",
        file_path="/home/user/Documents/invoice.docx.exe",
        file_name="invoice.docx.exe",
        sha256="3333333333333333333333333333333333333333333333333333333333333333",
        size=4096,
        is_executable=True
    )
    res_de = client.post(f"/api/v1/fim/verify/{dev_id}", json=de_evt.model_dump(mode='json'))
    assert res_de.status_code == 200
    assert res_de.json()["status"] == "NEW_FILE"

    # 4. File Rename Event
    rn_evt = FileChangeEventRequest(
        event_type="RENAMED",
        file_path="/home/user/Documents/invoice_renamed.exe",
        file_name="invoice_renamed.exe",
        old_path="/home/user/Documents/invoice.docx.exe",
        sha256="3333333333333333333333333333333333333333333333333333333333333333",
        size=4096,
        is_executable=True
    )
    res_rn = client.post(f"/api/v1/fim/verify/{dev_id}", json=rn_evt.model_dump(mode='json'))
    assert res_rn.status_code == 200
    assert "file_renamed_or_moved" in res_rn.json()["changes_detected"]

    # 5. File Deletion Event
    del_evt = FileChangeEventRequest(
        event_type="DELETED",
        file_path="/home/user/Documents/invoice_renamed.exe",
        file_name="invoice_renamed.exe"
    )
    res_del = client.post(f"/api/v1/fim/verify/{dev_id}", json=del_evt.model_dump(mode='json'))
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "DELETED"

    # 6. Response Action (Quarantine & Recalculate)
    res_act1 = client.post(f"/api/v1/fim/respond/{dev_id}", json={"file_path": "/home/user/Downloads/setup.exe", "action_type": "QUARANTINE"})
    assert res_act1.status_code == 200
    assert res_act1.json()["status"] == "SUCCESS"

    res_act2 = client.post(f"/api/v1/fim/respond/{dev_id}", json={"file_path": "/home/user/Downloads/setup.exe", "action_type": "RECALCULATE_BASELINE", "new_sha256": "9999999999999999999999999999999999999999999999999999999999999999", "new_size": 3000})
    assert res_act2.status_code == 200
    assert res_act2.json()["status"] == "SUCCESS"

    # 7. Timeline Generation Verification
    res_tl = client.get(f"/api/v1/fim/timeline/{dev_id}?file_path=/home/user/Downloads/setup.exe")
    assert res_tl.status_code == 200
    assert len(res_tl.json()["timeline"]) >= 3
