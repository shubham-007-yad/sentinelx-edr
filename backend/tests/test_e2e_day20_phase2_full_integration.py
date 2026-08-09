import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatSeverity, ThreatType, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.models.response_audit_log import ResponseAuditLog
from app.models.telemetry_log import UnifiedTelemetryLog, TelemetryCategoryEnum
from app.models.user import User, UserRole
from app.auth.jwt import create_access_token
from app.services import (
    device_service,
    usb_event_service,
    usb_scan_service,
    threat_service,
    alert_service,
    response_service,
    timeline_engine,
    investigation_case_service,
)
from app.detection.behavior.incident_correlator import incident_correlator


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def auth_headers(setup_db: Session):
    db = setup_db
    # Ensure analyst test user exists
    user = db.query(User).filter(User.username == "test_analyst_day20").first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            username="test_analyst_day20",
            email="analyst_day20@sentinelx.io",
            password_hash="hashed_pass_placeholder",
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(user)
    user.role = UserRole.ADMIN
    db.commit()
    db.refresh(user)

    token = create_access_token(subject=user.username, role=user.role.value if hasattr(user.role, 'value') else str(user.role))
    return {"Authorization": f"Bearer {token}"}


def test_day20_phase2_full_integration_12_stage_lifecycle(setup_db: Session, auth_headers: dict):
    """
    Day 20 Phase 2 — Full Integration Verification.
    Runs the complete 12-stage enterprise EDR lifecycle:
    Endpoint Registration ➔ Heartbeat ➔ USB Detection ➔ File Scan ➔
    Threat Detection ➔ IOC Correlation ➔ Alert ➔ WebSocket Notification ➔
    Investigation ➔ Response ➔ Audit Log ➔ Analytics

    Expected Result:
    Every stage succeeds and the SAME correlation_id can be used to reconstruct the incident.
    """
    db = setup_db
    client = TestClient(app)
    shared_correlation_id = str(uuid.uuid4())

    # =========================================================================
    # Stage 1: Endpoint Registration
    # =========================================================================
    reg_payload = {
        "hostname": "WORKSTATION-PHASE2-E2E",
        "ip_address": "192.168.1.188",
        "mac_address": "00:AA:BB:CC:DD:EE",
        "os_type": "WINDOWS",
        "os_version": "Windows 11 Enterprise 23H2",
        "agent_version": "v1.0.0"
    }
    reg_res = client.post("/api/v1/devices/register", json=reg_payload)
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"
    device_data = reg_res.json()
    device_id = device_data["id"]
    dev_uuid = uuid.UUID(device_id)
    assert device_data["status"] == "ONLINE"

    # =========================================================================
    # Stage 2: Endpoint Heartbeat
    # =========================================================================
    hb_payload = {
        "device_id": device_id,
        "status": "ONLINE"
    }
    hb_res = client.post("/api/v1/devices/heartbeat", json=hb_payload)
    assert hb_res.status_code == 200, f"Heartbeat failed: {hb_res.text}"
    assert hb_res.json()["status"] == "ONLINE"

    # =========================================================================
    # Stage 3: USB Detection Event
    # =========================================================================
    usb_evt_payload = {
        "device_id": device_id,
        "event_type": "INSERT",
        "drive_letter": "F:",
        "volume_label": "MALWARE_PHASE2_USB",
        "filesystem": "NTFS",
        "total_size": 32000000000,
        "free_space": 16000000000,
        "serial_number": "PHASE2-USB-8899"
    }
    usb_res = client.post("/api/v1/usb/events", json=usb_evt_payload)
    assert usb_res.status_code == 201, f"USB event creation failed: {usb_res.text}"
    usb_event_data = usb_res.json()
    usb_event_id = usb_event_data["id"]

    # =========================================================================
    # Stage 4: File Scan Upload
    # =========================================================================
    scan_payload = [
        {
            "usb_event_id": usb_event_id,
            "file_name": "q3_payroll_details.pdf.exe",
            "full_path": "F:\\q3_payroll_details.pdf.exe",
            "extension": ".exe",
            "file_size": 2048576,
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR Test Malware
            "is_hidden": True
        }
    ]
    scan_res = client.post("/api/v1/usb/scans", json=scan_payload)
    assert scan_res.status_code == 201, f"USB scan upload failed: {scan_res.text}"

    # =========================================================================
    # Stage 5: Threat Detection
    # =========================================================================
    threats_res = client.get(f"/api/v1/threats?usb_event_id={usb_event_id}", headers=auth_headers)
    assert threats_res.status_code == 200, f"Threat list failed: {threats_res.text}"
    threats_list = threats_res.json()
    assert len(threats_list) >= 1, "Threat engine should detect malicious file on USB"
    detected_threat = threats_list[0]
    threat_id = detected_threat["id"]

    # =========================================================================
    # Stage 6: IOC Correlation Engine
    # =========================================================================
    inc_obj = incident_correlator.correlate_event(
        device_id=device_id,
        subsystem="USB",
        rule_name=detected_threat["rule_name"],
        description=detected_threat["description"],
        severity="CRITICAL",
        pid=9912,
        process_name="q3_payroll_details.pdf.exe",
        file_path="F:\\q3_payroll_details.pdf.exe",
        existing_correlation_id=shared_correlation_id
    )
    assert inc_obj.correlation_id == shared_correlation_id
    assert inc_obj.severity == "CRITICAL"

    # Save correlated telemetry log with shared_correlation_id
    telemetry_log = UnifiedTelemetryLog(
        id=uuid.uuid4(),
        device_id=dev_uuid,
        category=TelemetryCategoryEnum.USB,
        event_type="USB_MALWARE_MATCH",
        source="USBCollector",
        correlation_id=uuid.UUID(shared_correlation_id),
        tenant_id="default_tenant",
        host_info={"hostname": "WORKSTATION-PHASE2-E2E", "ip_address": "192.168.1.188"},
        payload={"usb_event_id": usb_event_id, "threat_id": threat_id, "file_name": "q3_payroll_details.pdf.exe"}
    )
    db.add(telemetry_log)
    db.commit()

    # =========================================================================
    # Stage 7: Alert Engine Generation
    # =========================================================================
    alerts_res = client.get(f"/api/v1/alerts?device_id={device_id}", headers=auth_headers)
    assert alerts_res.status_code == 200, f"Alert list failed: {alerts_res.text}"
    alerts_list = alerts_res.json()
    assert len(alerts_list) >= 1, "Alert Engine must create alert for high severity threat"
    alert_id = alerts_list[0]["id"]

    # =========================================================================
    # Stage 8: WebSocket Notification Verification
    # =========================================================================
    # Check that websocket manager is operational and supports broadcast
    from app.core.websocket_manager import websocket_manager
    ws_broadcast = {
        "event": "INCIDENT_ALERT",
        "correlation_id": shared_correlation_id,
        "device_id": device_id,
        "alert_id": alert_id,
        "title": "CRITICAL USB Malware Outbreak Detected"
    }
    websocket_manager.broadcast_sync(ws_broadcast)

    # =========================================================================
    # Stage 9: Investigation & Incident Timeline Reconstruction
    # =========================================================================
    case_create_payload = {
        "title": "APT-Phase2 USB Trojan Outbreak Investigation",
        "description": "Multi-vector malware execution from rogue USB drive",
        "severity": "CRITICAL",
        "correlation_id": shared_correlation_id,
        "assigned_analyst": "analyst_day20",
        "linked_alert_ids": [alert_id],
        "linked_telemetry_ids": [str(telemetry_log.id)]
    }
    case_res = client.post("/api/v1/investigation/cases", json=case_create_payload, headers=auth_headers)
    assert case_res.status_code == 201, f"Case creation failed: {case_res.text}"
    case_data = case_res.json()
    assert case_data["correlation_id"] == shared_correlation_id

    # Reconstruct Incident Timeline using shared_correlation_id
    timeline_res = client.get(f"/api/v1/investigation/timeline/{shared_correlation_id}", headers=auth_headers)
    assert timeline_res.status_code == 200, f"Timeline reconstruction failed: {timeline_res.text}"
    timeline_data = timeline_res.json()
    assert timeline_data["correlation_id"] == shared_correlation_id
    assert len(timeline_data["timeline"]) >= 1, "Timeline must reconstruct events sharing correlation_id"

    # =========================================================================
    # Stage 10: Response Containment
    # =========================================================================
    response_payload = {
        "device_id": device_id,
        "action_type": "ISOLATE",
        "alert_id": alert_id,
        "initiated_by": "test_analyst_day20",
        "parameters": {"isolation_level": "STRICT_NETWORK_BLOCK"}
    }
    resp_res = client.post("/api/v1/responses/trigger", json=response_payload, headers=auth_headers)
    assert resp_res.status_code == 201, f"Response execution failed: {resp_res.text}"
    resp_data = resp_res.json()
    action_id = resp_data["id"]
    assert resp_data["action_type"] == "ISOLATE"

    # =========================================================================
    # Stage 11: Audit Log Persistence
    # =========================================================================
    audit_logs = db.query(ResponseAuditLog).filter(ResponseAuditLog.action_id == uuid.UUID(action_id)).all()
    assert len(audit_logs) >= 1, "Response Engine must generate audit log entries"
    assert audit_logs[0].actor == "test_analyst_day20"

    # =========================================================================
    # Stage 12: Executive Analytics Reflection
    # =========================================================================
    analytics_res = client.get("/api/v1/analytics/dashboard?timeframe_days=7", headers=auth_headers)
    assert analytics_res.status_code == 200, f"Analytics failed: {analytics_res.text}"
    analytics_data = analytics_res.json()
    assert analytics_data["top_metrics"]["total_endpoints"] >= 1
    assert "posture" in analytics_data
