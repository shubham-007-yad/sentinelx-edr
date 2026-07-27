import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatSeverity, ThreatType, ThreatStatus
from app.detection import DetectionEngine, threat_scorer
from app.services import threat_service


@pytest.fixture(scope="module")
def test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_complete_phase8_flow(test_db: Session, client: TestClient):
    """
    Verifies the complete end-to-end flow specified in Phase 8:
    Insert USB -> Scan Files -> Run Detection Rules -> Create Threat Records -> Display Threats
    """
    # -------------------------------------------------------------
    # STEP 1: Register Device & Simulate USB Insertion (Insert USB)
    # -------------------------------------------------------------
    dev_id = uuid.uuid4()
    device = Device(
        id=dev_id,
        hostname="WORKSTATION-PHASE8",
        os_type=OSType.WINDOWS,
        os_version="Windows 11 Pro 22H2",
        ip_address="192.168.1.150",
        agent_version="1.0.0",
        is_active=True
    )
    test_db.add(device)
    test_db.commit()

    usb_evt_id = uuid.uuid4()
    usb_event = USBEvent(
        id=usb_evt_id,
        device_id=dev_id,
        serial_number="PHASE8_STICK_001",
        drive_letter="E:",
        volume_label="SECURE_USB",
        event_type=USBEventType.INSERT
    )
    test_db.add(usb_event)
    test_db.commit()

    assert usb_event.id is not None

    # -------------------------------------------------------------
    # STEP 2: Scan Files on USB Drive (Scan Files)
    # -------------------------------------------------------------
    # Simulate scanning a USB containing various dangerous payloads & files
    scan_files_data = [
        # 1. Dangerous executable (.exe -> HIGH)
        {
            "file_name": "payload.exe",
            "full_path": "E:\\payload.exe",
            "extension": ".exe",
            "file_size": 2048576,
            "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            "is_hidden": False
        },
        # 2. Dangerous DLL (.dll -> HIGH)
        {
            "file_name": "helper.dll",
            "full_path": "E:\\helper.dll",
            "extension": ".dll",
            "file_size": 512000,
            "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
            "is_hidden": False
        },
        # 3. Double extension deceptive file (invoice.pdf.exe -> CRITICAL)
        {
            "file_name": "q3_invoice.pdf.exe",
            "full_path": "E:\\q3_invoice.pdf.exe",
            "extension": ".exe",
            "file_size": 1048576,
            "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
            "is_hidden": False
        },
        # 4. USB AutoRun Script (autorun.inf -> CRITICAL)
        {
            "file_name": "autorun.inf",
            "full_path": "E:\\autorun.inf",
            "extension": ".inf",
            "file_size": 128,
            "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
            "is_hidden": True
        },
        # 5. Known Malware (EICAR Hash -> CRITICAL)
        {
            "file_name": "eicar_test.com",
            "full_path": "E:\\eicar_test.com",
            "extension": ".com",
            "file_size": 68,
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "is_hidden": False
        },
        # 6. Benign document (.docx -> Clean)
        {
            "file_name": "report.docx",
            "full_path": "E:\\report.docx",
            "extension": ".docx",
            "file_size": 45000,
            "sha256": "5555555555555555555555555555555555555555555555555555555555555555",
            "is_hidden": False
        }
    ]

    scans: list[USBScanResult] = []
    for f in scan_files_data:
        scan_rec = USBScanResult(
            usb_event_id=usb_evt_id,
            file_name=f["file_name"],
            full_path=f["full_path"],
            extension=f["extension"],
            file_size=f["file_size"],
            sha256=f["sha256"],
            is_hidden=f["is_hidden"]
        )
        test_db.add(scan_rec)
        scans.append(scan_rec)

    test_db.commit()
    for s in scans:
        test_db.refresh(s)

    # -------------------------------------------------------------
    # STEP 3 & 4: Run Detection Rules & Create Threat Records
    # -------------------------------------------------------------
    created_threats = threat_service.analyze_and_record_threats(db=test_db, scan_results=scans)
    assert len(created_threats) >= 5  # 5 threats detected out of 6 scanned files

    # Verify severity standardization
    critical_threats = [t for t in created_threats if t.severity == ThreatSeverity.CRITICAL]
    high_threats = [t for t in created_threats if t.severity == ThreatSeverity.HIGH]

    assert len(critical_threats) >= 3  # double ext, autorun.inf, eicar
    assert len(high_threats) >= 2      # .exe, .dll

    # -------------------------------------------------------------
    # STEP 5: Display Threats via REST APIs (Display Threats)
    # -------------------------------------------------------------
    # 5a. GET /api/v1/threats
    res_list = client.get("/api/v1/threats")
    assert res_list.status_code == 200
    threats_data = res_list.json()
    assert len(threats_data) >= 5

    # Check columns in list output
    sample = threats_data[0]
    assert "file_name" in sample
    assert "threat_type" in sample
    assert "severity" in sample
    assert "rule_name" in sample
    assert "status" in sample
    assert "detected_at" in sample

    # 5b. GET /api/v1/threats with Severity Filter
    res_crit = client.get("/api/v1/threats?severity=CRITICAL")
    assert res_crit.status_code == 200
    assert all(t["severity"] == "CRITICAL" for t in res_crit.json())

    # 5c. GET /api/v1/threats with Search Filter
    res_search = client.get("/api/v1/threats?search=q3_invoice")
    assert res_search.status_code == 200
    assert any("q3_invoice" in t["file_name"] for t in res_search.json())

    # 5d. GET /api/v1/threats/{id}
    target_id = created_threats[0].id
    res_detail = client.get(f"/api/v1/threats/{target_id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == str(target_id)

    # 5e. PATCH /api/v1/threats/{id}/status
    res_patch = client.patch(
        f"/api/v1/threats/{target_id}/status",
        json={"status": "RESOLVED"}
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] == "RESOLVED"

    # 5f. GET /api/v1/threats/summary
    res_summary = client.get("/api/v1/threats/summary")
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert summary_data["total_threats"] >= 5
    assert summary_data["severity_breakdown"]["CRITICAL"] >= 3
    assert summary_data["severity_breakdown"]["HIGH"] >= 2
