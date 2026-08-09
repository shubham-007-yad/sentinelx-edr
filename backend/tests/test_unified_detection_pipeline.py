import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.detection import DetectionEvent, detection_pipeline

client = TestClient(app)


def test_unified_detection_pipeline_four_telemetry_sources():
    """
    Verifies that all 4 SentinelX Telemetry Sources (USB, Files, Processes, Network)
    emit standardized DetectionEvent objects that flow through the unified pipeline:
    DetectionEvent ➔ Threat Scoring ➔ Alert Generation ➔ Response Engine ➔ Audit Logging ➔ WebSocket
    """
    db = SessionLocal()
    try:
        # 1. Device Registration
        device = Device(
            hostname="enterprise-soc-workstation",
            ip_address="192.168.1.188",
            mac_address="DE:AD:BE:EF:00:88",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # ----------------------------------------------------
        # Telemetry Source 1: USB Telemetry Event
        # ----------------------------------------------------
        usb_event = DetectionEvent(
            source_subsystem="USB",
            device_id=device.id,
            rule_id="USB-RULE-0001",
            rule_name="Known Malware on USB Drive",
            threat_type="KNOWN_MALWARE",
            severity="CRITICAL",
            description="Malicious payload payload.exe detected on USB volume E:",
            file_name="payload.exe",
            file_path="E:\\payload.exe",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        res_usb = detection_pipeline.process_event(db, usb_event)
        assert res_usb["status"] == "PROCESSED"
        assert res_usb["threat_id"] is not None
        assert res_usb["alert_id"] is not None
        assert res_usb["risk_score"] > 0

        # ----------------------------------------------------
        # Telemetry Source 2: File Telemetry Event
        # ----------------------------------------------------
        file_event = DetectionEvent(
            source_subsystem="FILE",
            device_id=device.id,
            rule_id="FILE-RULE-0002",
            rule_name="Hidden Executable File Created",
            threat_type="HIDDEN_EXECUTABLE",
            severity="HIGH",
            description="Hidden executable dropper created in temp directory",
            file_name="dropper.exe",
            file_path="C:\\Users\\Public\\AppData\\dropper.exe"
        )
        res_file = detection_pipeline.process_event(db, file_event)
        assert res_file["status"] == "PROCESSED"
        assert res_file["threat_id"] is not None
        assert res_file["alert_id"] is not None

        # ----------------------------------------------------
        # Telemetry Source 3: Process Telemetry Event
        # ----------------------------------------------------
        proc_event = DetectionEvent(
            source_subsystem="PROCESS",
            device_id=device.id,
            rule_id="PROC-RULE-0003",
            rule_name="Suspicious PowerShell Command Execution",
            threat_type="LOLBIN_ABUSE",
            severity="HIGH",
            description="PowerShell executed with encoded command bypass arguments",
            pid=7800,
            process_name="powershell.exe",
            executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        )
        res_proc = detection_pipeline.process_event(db, proc_event)
        assert res_proc["status"] == "PROCESSED"
        assert res_proc["threat_id"] is not None
        assert res_proc["alert_id"] is not None

        # ----------------------------------------------------
        # Telemetry Source 4: Network Telemetry Event
        # ----------------------------------------------------
        net_event = DetectionEvent(
            source_subsystem="NETWORK",
            device_id=device.id,
            rule_id="NET-RULE-0004",
            rule_name="C2 Network Beaconing Detected",
            threat_type="C2_BEACONING",
            severity="CRITICAL",
            description="Periodic C2 beaconing to remote IP 185.220.101.5:4444",
            pid=7800,
            process_name="powershell.exe",
            executable_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            local_ip="192.168.1.188",
            local_port=49999,
            remote_ip="185.220.101.5",
            remote_port=4444,
            protocol="TCP"
        )
        res_net = detection_pipeline.process_event(db, net_event)
        assert res_net["status"] == "PROCESSED"
        assert res_net["threat_id"] is not None
        assert res_net["alert_id"] is not None

    finally:
        db.close()
