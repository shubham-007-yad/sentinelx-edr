import pytest
from datetime import datetime, timezone
from uuid import uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.file_integrity_record import FileIntegrityRecord
from app.schemas.file_integrity import (
    FileIntegrityRecordCreate, FileIntegrityRecordOut, FileIntegrityBatchIngestRequest
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
def test_device(db_session):
    device = Device(
        hostname="fim-test-host",
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:DD:EE:FF",
        os_type=OSType.LINUX,
        os_version="Ubuntu 22.04",
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_file_integrity_model_and_service(db_session, test_device):
    rec_in = FileIntegrityRecordCreate(
        file_path="/etc/shadow",
        file_name="shadow",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size=1234,
        last_modified=datetime.now(timezone.utc),
        owner="root",
        is_executable=False
    )

    created = file_integrity_service.upsert_file_integrity_record(
        db=db_session,
        device_id=test_device.id,
        record_in=rec_in
    )

    assert created.id is not None
    assert created.device_id == test_device.id
    assert created.file_path == "/etc/shadow"
    assert created.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Query record
    records = file_integrity_service.get_file_integrity_records(
        db=db_session,
        device_id=test_device.id,
        file_name="shadow"
    )
    assert len(records) >= 1
    assert records[0].file_path == "/etc/shadow"


def test_file_integrity_api_endpoints(client, test_device):
    payload = {
        "records": [
            {
                "file_path": "/etc/pam.d/common-auth",
                "file_name": "common-auth",
                "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
                "size": 512,
                "owner": "root",
                "is_executable": False
            },
            {
                "file_path": "/usr/local/bin/backdoor",
                "file_name": "backdoor",
                "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "size": 4096,
                "owner": "www-data",
                "is_executable": True
            }
        ]
    }

    # Ingest baseline
    res = client.post(f"/api/v1/fim/baseline/{test_device.id}", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert len(data) == 2
    assert data[0]["file_name"] == "common-auth"

    # List baseline records
    list_res = client.get(f"/api/v1/fim/records?device_id={test_device.id}&is_executable=true")
    assert list_res.status_code == 200
    exec_data = list_res.json()
    assert len(exec_data) == 1
    assert exec_data[0]["file_name"] == "backdoor"
    assert exec_data[0]["is_executable"] is True
