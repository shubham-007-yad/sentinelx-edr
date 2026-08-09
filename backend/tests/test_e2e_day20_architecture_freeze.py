import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.telemetry_log import UnifiedTelemetryLog, TelemetryCategoryEnum
from app.models.threat import Threat, ThreatSeverity, ThreatType
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.schemas.telemetry import BaseTelemetryEvent, TelemetryCategory, TelemetryIngestBatchRequest
from app.detection.pipeline import detection_pipeline
from app.detection.event import DetectionEvent
from app.detection.behavior.incident_correlator import incident_correlator, SubsystemAlertEvent
from app.services import response_service, telemetry_service, threat_hunting_engine


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()


def test_day20_phase1_architecture_freeze_complete_flow(setup_db: Session):
    """
    Day 20 Phase 1 — Comprehensive Architecture Freeze Master Validation.
    Validates the end-to-end 8-stage enterprise core architecture:
    SentinelX Agent -> Telemetry Envelope (v1.0) -> Unified Telemetry API -> DB/Queue ->
    7 Detection Engines -> Threat/Correlation Engine -> Alert Engine -> Response Engine.
    """
    db = setup_db
    client = TestClient(app)

    # Stage 1: Register Target Endpoint Agent Device
    dev_uuid = uuid.uuid4()
    device = Device(
        id=dev_uuid,
        hostname="WORKSTATION-DAY20-FREEZE",
        ip_address="192.168.1.120",
        mac_address="00:11:22:33:44:55",
        os_type=OSType.WINDOWS,
        os_version="Windows 11 Pro 23H2",
        agent_version="v1.0.0",
        status=DeviceStatus.ONLINE
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    # Stage 2: Create Standardized Telemetry Envelope (schema v1.0) for all 7 Detection Engines
    correlation_id = uuid.uuid4()

    telemetry_events = [
        BaseTelemetryEvent(
            device_id=dev_uuid,
            category=TelemetryCategory.USB,
            event_type="USB_INSERTED",
            source="USBCollector",
            correlation_id=correlation_id,
            schema_version="1.0",
            payload={"drive_letter": "E:", "volume_label": "ATTACK_DRIVE", "serial_number": "DAY20-USB-99"}
        ),
        BaseTelemetryEvent(
            device_id=dev_uuid,
            category=TelemetryCategory.PROCESS,
            event_type="PROCESS_START",
            source="ProcessCollector",
            correlation_id=correlation_id,
            schema_version="1.0",
            payload={"pid": 4820, "name": "powershell.exe", "cmdline": "powershell.exe -e aW52b2tlLWV4cHJlc3Npb24=", "ppid": 1200}
        ),
        BaseTelemetryEvent(
            device_id=dev_uuid,
            category=TelemetryCategory.NETWORK,
            event_type="OUTBOUND_CONNECT",
            source="NetworkCollector",
            correlation_id=correlation_id,
            schema_version="1.0",
            payload={"pid": 4820, "remote_ip": "185.220.101.5", "remote_port": 443, "protocol": "TCP"}
        ),
        BaseTelemetryEvent(
            device_id=dev_uuid,
            category=TelemetryCategory.FILE_INTEGRITY,
            event_type="FILE_MODIFIED",
            source="FIMCollector",
            correlation_id=correlation_id,
            schema_version="1.0",
            payload={"file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "change_type": "MODIFIED", "sha256": "abcdef1234567890"}
        ),
        BaseTelemetryEvent(
            device_id=dev_uuid,
            category=TelemetryCategory.SECURITY_EVENT,
            event_type="FAILED_LOGON",
            source="SecurityEventCollector",
            correlation_id=correlation_id,
            schema_version="1.0",
            payload={"event_id": 4625, "username": "Administrator", "workstation": "ATTACKER-BOX"}
        ),
        BaseTelemetryEvent(
            device_id=dev_uuid,
            category=TelemetryCategory.IOC_INTELLIGENCE,
            event_type="IOC_MATCH",
            source="IOCCollector",
            correlation_id=correlation_id,
            schema_version="1.0",
            payload={"ioc_type": "SHA256", "ioc_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "malware_family": "EICAR Test File"}
        ),
        BaseTelemetryEvent(
            device_id=dev_uuid,
            category=TelemetryCategory.RANSOMWARE,
            event_type="MASS_RENAME",
            source="RansomwareCollector",
            correlation_id=correlation_id,
            schema_version="1.0",
            payload={"pid": 4820, "renamed_count": 85, "extension": ".locked"}
        )
    ]

    # Stage 3: Ingest through Unified Telemetry API Service
    ingest_result = telemetry_service.ingest_telemetry_batch(
        db=db,
        device_id=dev_uuid,
        events=telemetry_events
    )
    assert ingest_result["status"] == "SUCCESS"
    assert ingest_result["events_processed"] == 7

    # Stage 4: Verify PostgreSQL Storage & Schema v1.0 Telemetry Logs
    stored_logs = db.query(UnifiedTelemetryLog).filter(UnifiedTelemetryLog.device_id == dev_uuid).all()
    assert len(stored_logs) == 7
    categories_stored = {log.category.value for log in stored_logs}
    assert TelemetryCategoryEnum.USB.value in categories_stored
    assert TelemetryCategoryEnum.PROCESS.value in categories_stored
    assert TelemetryCategoryEnum.NETWORK.value in categories_stored
    assert TelemetryCategoryEnum.FILE_INTEGRITY.value in categories_stored
    assert TelemetryCategoryEnum.SECURITY_EVENT.value in categories_stored
    assert TelemetryCategoryEnum.IOC_INTELLIGENCE.value in categories_stored
    assert TelemetryCategoryEnum.RANSOMWARE.value in categories_stored

    # Stage 5: Evaluate through Unified Detection Pipeline & Threat/Correlation Engine
    det_event = DetectionEvent(
        source_subsystem="RANSOMWARE",
        rule_id="RULE-RANSOMWARE-01",
        rule_name="Mass File Encryption & Extension Change",
        severity="CRITICAL",
        description="Process 4820 renamed 85 files to .locked in short interval",
        device_id=dev_uuid,
        pid=4820,
        process_name="powershell.exe",
        threat_type="RANSOMWARE_BEHAVIOR"
    )
    pipeline_res = detection_pipeline.process_event(db=db, event=det_event)
    assert pipeline_res["status"] == "PROCESSED"
    assert pipeline_res["auto_action"] == "TERMINATE_PROCESS"
    assert pipeline_res["risk_score"] == 100

    # Stage 6: Verify Multi-Vector Incident Correlation Engine
    inc_obj = incident_correlator.correlate_event(
        device_id=str(dev_uuid),
        subsystem="RANSOMWARE",
        rule_name="Mass File Encryption",
        description="Cryptographic mass rename detected",
        severity="CRITICAL",
        pid=4820,
        process_name="powershell.exe",
        existing_correlation_id=str(correlation_id)
    )
    assert inc_obj.severity == "CRITICAL"

    # Stage 7: Verify Alert Generation Engine
    alerts = db.query(Alert).filter(Alert.device_id == dev_uuid).all()
    assert len(alerts) >= 1
    assert alerts[0].severity == AlertSeverity.CRITICAL

    # Stage 8: Verify Response Engine Automated Action Persistence
    actions = db.query(ResponseAction).filter(ResponseAction.device_id == dev_uuid).all()
    assert len(actions) >= 1
    assert actions[0].action_type in [ResponseActionType.TERMINATE_PROCESS, ResponseActionType.ISOLATE, ResponseActionType.BLOCK_IP]
    assert actions[0].initiated_by == "AUTO_PIPELINE"
