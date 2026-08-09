import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.threat import ThreatType, ThreatSeverity
from app.detection.rules.fim_rules import (
    FIMExecutableInDownloadsRule, FIMDoubleExtensionRule,
    FIMStartupModificationRule, FIMMassFileModificationRule
)


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
def e2e_device(db_session):
    device = Device(
        hostname="fim-e2e-node",
        ip_address="192.168.1.100",
        os_type=OSType.LINUX,
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_e2e_day11_fim_complete_pipeline(client, e2e_device):
    # 1. Ingest Baseline Snapshot
    baseline_payload = {
        "records": [
            {
                "file_path": "/home/user/Documents/report.pdf",
                "file_name": "report.pdf",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 1024,
                "owner": "user",
                "is_executable": False
            },
            {
                "file_path": "/etc/systemd/system/sentinelx.service",
                "file_name": "sentinelx.service",
                "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "size": 400,
                "owner": "root",
                "is_executable": False
            }
        ]
    }
    baseline_res = client.post(f"/api/v1/fim/baseline/{e2e_device.id}", json=baseline_payload)
    assert baseline_res.status_code == 201
    assert len(baseline_res.json()) == 2

    # 2. Verify File Change API
    change_payload = {
        "event_type": "MODIFIED",
        "file_path": "/home/user/Documents/report.pdf",
        "file_name": "report.pdf",
        "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "size": 1500,
        "is_executable": False,
        "owner": "user"
    }
    verify_res = client.post(f"/api/v1/fim/verify/{e2e_device.id}", json=change_payload)
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["is_changed"] is True
    assert "sha256_mismatch" in v_data["changes_detected"]

    # 3. Test FIM Rules Execution
    r1 = FIMExecutableInDownloadsRule().evaluate("setup.exe", "/home/user/Downloads/setup.exe", ".exe", 2048, "hash1", False, True, "CREATED")
    assert r1 is not None and r1.threat_type == ThreatType.FIM_EXECUTABLE_IN_DOWNLOADS

    r2 = FIMDoubleExtensionRule().evaluate("invoice.docx.exe", "/home/user/Documents/invoice.docx.exe", ".exe", 4096, "hash2", False, True, "CREATED")
    assert r2 is not None and r2.severity == ThreatSeverity.CRITICAL

    r3 = FIMStartupModificationRule().evaluate("persist.sh", "/etc/init.d/persist.sh", ".sh", 512, "hash3", False, True, "CREATED")
    assert r3 is not None and r3.threat_type == ThreatType.FIM_STARTUP_MODIFICATION

    r4 = FIMMassFileModificationRule().evaluate("file.doc", "/home/user/Documents/file.doc", ".doc", 100, "hash4", modification_count=12)
    assert r4 is not None and r4.threat_type == ThreatType.FIM_MASS_FILE_MODIFICATION

    # 4. Fetch All Integrity Records Endpoint
    records_res = client.get(f"/api/v1/fim/records?device_id={e2e_device.id}")
    assert records_res.status_code == 200
    assert len(records_res.json()) >= 2
