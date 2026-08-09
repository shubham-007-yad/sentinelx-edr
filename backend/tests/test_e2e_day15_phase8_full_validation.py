import uuid
from datetime import datetime, timezone, timedelta
import pytest

from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, OSType
from app.models.investigation_case import CaseSeverity, CaseStatus
from app.schemas.investigation_case import (
    InvestigationCaseCreate,
    InvestigationCaseUpdate,
    CaseNoteCreate,
    CaseEvidenceCreate,
    LinkAlertsPayload,
    LinkTelemetryPayload
)
from app.schemas.timeline import SequenceEventItem
from app.schemas.threat_hunting import ThreatHuntingQuery
from app.services import (
    investigation_case_service,
    timeline_engine,
    threat_hunting_engine,
    investigation_report_service
)
from app.detection.behavior.incident_correlator import IncidentCorrelationEngine


def test_day15_phase8_complete_validation_suite():
    """
    Phase 8 — Master End-to-End Testing Suite for Day 15 Threat Hunting & Investigation Console.
    Validates all 7 criteria in sequence:
    1. Create investigation case
    2. Timeline generation
    3. Threat hunting search queries
    4. Cross-telemetry correlation (1 incident, not 6 alerts)
    5. Evidence and note linking
    6. PDF & JSON Report generation
    7. Dashboard rendering metrics
    """
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        init_db(db)
        correlation_id = str(uuid.uuid4())
        base_time = datetime.now(timezone.utc) - timedelta(minutes=10)


        # Step 1: Create Endpoint Device
        device = Device(
            hostname="DESKTOP-DAY15-VAL",
            ip_address="192.168.1.155",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        device_id = device.id

        # -------------------------------------------------------------
        # VALIDATION 1: Create Investigation
        # -------------------------------------------------------------
        case_in = InvestigationCaseCreate(
            title="APT-Day15 Multi-Vector USB Ransomware Attack",
            severity=CaseSeverity.CRITICAL,
            status=CaseStatus.OPEN,
            assigned_to="SOC_Lead_Analyst",
            correlation_id=correlation_id,
            summary="Multi-stage attack initiated from infected USB drive resulting in C2 connection and ransomware encryption."
        )
        case = investigation_case_service.create_investigation_case(db, case_in)
        assert case is not None, "Failed Validation 1: Create Investigation case returned None"
        assert case.id is not None
        assert case.title == "APT-Day15 Multi-Vector USB Ransomware Attack"
        assert case.status == CaseStatus.OPEN
        case_id = case.id
        print("✅ Validation 1 Passed: Create Investigation Case")

        # -------------------------------------------------------------
        # VALIDATION 2: Timeline Generation
        # -------------------------------------------------------------
        events = [
            SequenceEventItem(category="USB", title="USB inserted", description="Removable drive E: inserted", severity="INFO", timestamp=base_time),
            SequenceEventItem(category="USB", title="USB scan started", description="AV scan started on E:", severity="INFO", timestamp=base_time + timedelta(seconds=10)),
            SequenceEventItem(category="PROCESS", title="installer.exe detected", description="Execution of E:\\installer.exe", severity="HIGH", timestamp=base_time + timedelta(seconds=60)),
            SequenceEventItem(category="THREAT", title="Threat created", description="Double Extension Threat Detected", severity="CRITICAL", timestamp=base_time + timedelta(seconds=65)),
            SequenceEventItem(category="PROCESS", title="powershell.exe started", description="powershell.exe -ExecutionPolicy Bypass", severity="HIGH", timestamp=base_time + timedelta(seconds=120)),
            SequenceEventItem(category="NETWORK", title="Network connection opened", description="TCP Outbound to 198.51.100.99:443", severity="HIGH", timestamp=base_time + timedelta(seconds=130)),
            SequenceEventItem(category="ALERT", title="Alert generated", description="C2 Communication Alert", severity="CRITICAL", timestamp=base_time + timedelta(seconds=180)),
            SequenceEventItem(category="RESPONSE", title="Endpoint isolated", description="Host network isolated", severity="CRITICAL", timestamp=base_time + timedelta(seconds=185))
        ]
        timeline_res = timeline_engine.ingest_correlated_sequence(
            db=db,
            device_id=device_id,
            correlation_id=correlation_id,
            events=events
        )
        assert timeline_res is not None
        assert timeline_res.total_events >= 8
        titles = [ev.title for ev in timeline_res.timeline]
        assert "USB inserted" in titles
        assert "Endpoint isolated" in titles
        print("✅ Validation 2 Passed: Timeline Generation (8 Chronological Events)")

        # -------------------------------------------------------------
        # VALIDATION 3: Search Queries (Threat Hunting)
        # -------------------------------------------------------------
        hunt_q = ThreatHuntingQuery(
            process="powershell.exe",
            min_severity="HIGH",
            time_range_hours=24.0
        )
        hunt_res = threat_hunting_engine.execute_threat_hunt(db, hunt_q)
        assert hunt_res is not None
        assert hunt_res.total_matches >= 1
        print("✅ Validation 3 Passed: Threat Hunting Search Queries (process=powershell.exe AND severity>=HIGH)")

        # -------------------------------------------------------------
        # VALIDATION 4: Correlation (One Incident, Not Multiple Separate Alerts)
        # -------------------------------------------------------------
        corr_engine = IncidentCorrelationEngine(correlation_window_seconds=600.0)
        corr_id = str(uuid.uuid4())
        dev_str = str(device_id)

        corr_engine.correlate_event(device_id=dev_str, subsystem="USB", rule_name="USB Insert", description="USB E: inserted", existing_correlation_id=corr_id)
        corr_engine.correlate_event(device_id=dev_str, subsystem="PROCESS", rule_name="installer.exe", description="installer.exe executed", existing_correlation_id=corr_id)
        corr_engine.correlate_event(device_id=dev_str, subsystem="PROCESS", rule_name="Process Started", description="powershell.exe started", existing_correlation_id=corr_id)
        corr_engine.correlate_event(device_id=dev_str, subsystem="NETWORK", rule_name="Network Connection", description="C2 connection", existing_correlation_id=corr_id)
        corr_engine.correlate_event(device_id=dev_str, subsystem="THREAT", rule_name="IOC Match", description="C2 IP match", existing_correlation_id=corr_id)
        corr_engine.correlate_event(device_id=dev_str, subsystem="RANSOMWARE", rule_name="Ransomware Behavior", description="Mass encryption", existing_correlation_id=corr_id)
        corr_engine.correlate_event(device_id=dev_str, subsystem="RESPONSE", rule_name="Response", description="Device isolated", existing_correlation_id=corr_id)

        incidents = corr_engine.list_unified_incidents(device_id=dev_str)
        assert len(incidents) == 1, f"Correlation failed: Analyst should see 1 incident, found {len(incidents)}"
        assert incidents[0]["total_correlated_alerts"] == 7
        assert len(incidents[0]["subsystems_involved"]) == 6
        print("✅ Validation 4 Passed: Cross-Telemetry Correlation (1 Unified Incident)")

        # -------------------------------------------------------------
        # VALIDATION 5: Evidence & Note Linking
        # -------------------------------------------------------------
        note = investigation_case_service.add_case_note(
            db, case_id, CaseNoteCreate(author="SOC_Lead_Analyst", note_text="Confirmed C2 IP 198.51.100.99 match.")
        )
        assert note is not None

        evidence = investigation_case_service.add_case_evidence(
            db, case_id, CaseEvidenceCreate(evidence_type="FILE_HASH", title="Payload SHA-256", file_path_or_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        )
        assert evidence is not None

        linked_case = investigation_case_service.link_alerts_to_case(db, case_id, [str(uuid.uuid4())])
        assert len(linked_case.linked_alert_ids) >= 1

        fetched_case = investigation_case_service.get_case_by_id(db, case_id)
        assert len(fetched_case.notes) >= 1
        assert len(fetched_case.evidence_items) >= 1
        print("✅ Validation 5 Passed: Evidence, Notes, and Alert Linking")

        # -------------------------------------------------------------
        # VALIDATION 6: Report Generation (PDF & JSON)
        # -------------------------------------------------------------
        report_data = investigation_report_service.generate_report_data(db, case_id=case_id, correlation_id=correlation_id)
        assert report_data is not None
        assert report_data.executive_summary is not None
        assert report_data.technical_report is not None
        assert len(report_data.mitre_attack_mapping) >= 1

        json_out = report_data.model_dump()
        assert "executive_summary" in json_out

        pdf_bytes = investigation_report_service.export_report_pdf(report_data)
        assert pdf_bytes.startswith(b"%PDF"), "PDF export failed %PDF binary check"
        print("✅ Validation 6 Passed: Report Generation (PDF & JSON Exports)")

        # -------------------------------------------------------------
        # VALIDATION 7: Dashboard Rendering
        # -------------------------------------------------------------
        dash_summary = investigation_case_service.get_dashboard_summary(db)
        assert dash_summary is not None
        assert "open_cases_count" in dash_summary
        assert "recent_incidents" in dash_summary
        assert "response_actions" in dash_summary
        assert "related_devices" in dash_summary
        print("✅ Validation 7 Passed: Dashboard Rendering Metrics")

    finally:
        db.close()
