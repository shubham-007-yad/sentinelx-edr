import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.detection import DetectionEngine
from app.models.threat import ThreatSeverity, ThreatType, ThreatStatus

client = TestClient(app)


def test_threat_engine_known_malware():
    engine = DetectionEngine()
    findings = engine.evaluate_file(
        file_name="clean_looking.exe",
        full_path="E:\\clean_looking.exe",
        extension=".exe",
        file_size=1024,
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR hash
        is_hidden=False
    )
    assert len(findings) >= 1
    malware_finding = next(f for f in findings if f.threat_type == ThreatType.KNOWN_MALWARE)
    assert malware_finding.severity == ThreatSeverity.CRITICAL
    assert "Known Malicious" in malware_finding.rule_name


def test_threat_engine_double_extension():
    engine = DetectionEngine()
    findings = engine.evaluate_file(
        file_name="invoice_2026.pdf.exe",
        full_path="E:\\Documents\\invoice_2026.pdf.exe",
        extension=".exe",
        file_size=50000,
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        is_hidden=False
    )
    assert len(findings) >= 1
    double_ext = next(f for f in findings if f.threat_type == ThreatType.DOUBLE_EXTENSION)
    assert double_ext.severity == ThreatSeverity.CRITICAL


def test_threat_engine_hidden_executable():
    engine = DetectionEngine()
    findings = engine.evaluate_file(
        file_name=".secret_stealer.vbs",
        full_path="E:\\.secret_stealer.vbs",
        extension=".vbs",
        file_size=2048,
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        is_hidden=True
    )
    assert any(f.threat_type == ThreatType.HIDDEN_EXECUTABLE for f in findings)


def test_threat_engine_autorun():
    engine = DetectionEngine()
    findings = engine.evaluate_file(
        file_name="autorun.inf",
        full_path="E:\\autorun.inf",
        extension=".inf",
        file_size=128,
        sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        is_hidden=False
    )
    assert any(f.threat_type == ThreatType.AUTORUN_SCRIPT for f in findings)


def test_threat_engine_anomalous_file():
    engine = DetectionEngine()
    findings = engine.evaluate_file(
        file_name="svchost.exe",
        full_path="E:\\svchost.exe",
        extension=".exe",
        file_size=4096,
        sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        is_hidden=False
    )
    assert any(f.threat_type == ThreatType.ANOMALOUS_FILE for f in findings)


def test_threat_api_auto_detection_on_scan_upload():
    # 1. Register device
    dev_res = client.post("/api/v1/devices/register", json={
        "hostname": "PHASE2-TEST-PC",
        "ip_address": "192.168.1.105",
        "mac_address": "AA:BB:CC:DD:EE:FE",
        "os_type": "WINDOWS",
        "agent_version": "1.0.0"
    })
    assert dev_res.status_code == 201
    device_id = dev_res.json()["id"]

    # 2. Record USB event
    event_res = client.post("/api/v1/usb/events", json={
        "device_id": device_id,
        "event_type": "INSERT",
        "drive_letter": "E:",
        "volume_label": "MALWARE_TEST_USB",
        "filesystem": "FAT32",
        "total_size": 16000000000,
        "free_space": 8000000000,
        "serial_number": "MAL-9999"
    })
    assert event_res.status_code == 201
    usb_event_id = event_res.json()["id"]

    # 3. Upload USB scan payload with malware file
    scan_res = client.post("/api/v1/usb/scans", json=[
        {
            "usb_event_id": usb_event_id,
            "file_name": "quarterly_report.pdf.exe",
            "full_path": "E:\\quarterly_report.pdf.exe",
            "extension": ".exe",
            "file_size": 1048576,
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR
            "is_hidden": False
        },
        {
            "usb_event_id": usb_event_id,
            "file_name": "clean_document.pdf",
            "full_path": "E:\\clean_document.pdf",
            "extension": ".pdf",
            "file_size": 204800,
            "sha256": "9999999999999999999999999999999999999999999999999999999999999999",
            "is_hidden": False
        }
    ])
    assert scan_res.status_code == 201

    # 4. Verify threat records were automatically generated in backend
    threats_res = client.get(f"/api/v1/threats?usb_event_id={usb_event_id}")
    assert threats_res.status_code == 200
    threats = threats_res.json()
    assert len(threats) >= 1

    # 5. Verify Threat Summary API
    summary_res = client.get("/api/v1/threats/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()
    assert summary["total_threats"] >= 1
    assert summary["severity_breakdown"]["CRITICAL"] >= 1

    # 6. Verify Threat Detail & Patch Status API
    threat_id = threats[0]["id"]
    detail_res = client.get(f"/api/v1/threats/{threat_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["status"] == "NEW"

    patch_res = client.patch(f"/api/v1/threats/{threat_id}", json={
        "status": "RESOLVED"
    })
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "RESOLVED"
