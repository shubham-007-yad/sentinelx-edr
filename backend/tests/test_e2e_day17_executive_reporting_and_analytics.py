"""
Day 17 Phase 8 — Comprehensive End-to-End Validation Suite for Executive Reporting & Security Analytics

Validates:
1. Metric calculations (Posture, KPIs, MTTA, MTTR, SLA compliance)
2. Trend generation (6 multi-stream time-series across 24h, 7d, 30d, and custom ranges)
3. MITRE ATT&CK analytics (Matrix heatmap, technique frequencies, tactic breakdowns, coverage %)
4. Risk score calculations (Signal weights, contributing factors, recommended actions, risk levels)
5. Report generation (Executive & Technical report packages)
6. Export formats (PDF, CSV, JSON streams)
7. Dashboard rendering & API integration (/analytics/dashboard, /analytics/top-metrics, /scheduled-reports)
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.db.init_db import init_db

from app.models.device import Device, DeviceStatus, OSType
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.models.usb_event import USBEvent, USBEventType
from app.models.network_connection import NetworkConnection
from app.models.process_audit_log import ProcessAuditLog, ProcessEventType
from app.models.telemetry_log import UnifiedTelemetryLog, TelemetryCategoryEnum

from app.analytics.engine import AnalyticsEngine
from app.analytics.aggregation import TelemetryAggregator
from app.analytics.metrics import BusinessMetricsCalculator
from app.analytics.trends import TrendAnalyzer
from app.analytics.mitre import MitreMapper
from app.analytics.reporting import ExecutiveReporter

client = TestClient(app)


def get_admin_headers():
    db = SessionLocal()
    init_db(db)
    db.close()
    res = client.post(
        "/api/v1/auth/login/json",
        json={"username_or_email": "admin", "password": "AdminPassword123!"}
    )
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_e2e_day17_phase8_complete_validation():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    headers = get_admin_headers()

    try:
        now = datetime.now(timezone.utc)

        # ---------------------------------------------------------------------
        # 1. SEED TEST INFRASTRUCTURE DATA
        # ---------------------------------------------------------------------
        dev_host1 = f"e2e-exec-pc-{uuid.uuid4().hex[:6]}"
        dev_host2 = f"e2e-db-srv-{uuid.uuid4().hex[:6]}"

        dev1 = Device(
            hostname=dev_host1,
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE,
            ip_address="192.168.10.50",
            last_seen=now - timedelta(minutes=5)
        )
        dev2 = Device(
            hostname=dev_host2,
            os_type=OSType.LINUX,
            status=DeviceStatus.ISOLATED,
            ip_address="192.168.10.100",
            last_seen=now - timedelta(minutes=2)
        )
        db.add_all([dev1, dev2])
        db.commit()

        # Seed Threats (Known Malware, PowerShell, IOC Match)
        t1 = Threat(
            threat_type=ThreatType.KNOWN_MALWARE,
            severity=ThreatSeverity.CRITICAL,
            rule_name="Ransomware Mass File Encryption Detected",
            description="High frequency modification of files.",
            status=ThreatStatus.NEW,
            detected_at=now - timedelta(minutes=45)
        )
        t2 = Threat(
            threat_type=ThreatType.SUSPICIOUS_POWERSHELL,
            severity=ThreatSeverity.HIGH,
            rule_name="Encoded PowerShell Injection",
            description="PowerShell executed with encoded payload.",
            status=ThreatStatus.ACKNOWLEDGED,
            detected_at=now - timedelta(hours=3)
        )
        t3 = Threat(
            threat_type=ThreatType.BLACK_LISTED_IP,
            severity=ThreatSeverity.CRITICAL,
            rule_name="C2 Server Outbound Connection",
            description="Outbound TCP traffic to malicious IP.",
            status=ThreatStatus.RESOLVED,
            detected_at=now - timedelta(hours=6)
        )
        db.add_all([t1, t2, t3])
        db.commit()

        # Seed Alerts
        a1 = Alert(
            threat_id=t1.id,
            device_id=dev2.id,
            title="CRITICAL: Ransomware Activity on DB Server",
            message="Immediate containment required.",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.UNREAD,
            created_at=now - timedelta(minutes=45)
        )
        a2 = Alert(
            threat_id=t2.id,
            device_id=dev1.id,
            title="HIGH: Obfuscated Script Execution",
            message="PowerShell bypass detected.",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.ACKNOWLEDGED,
            created_at=now - timedelta(hours=3),
            acknowledged_at=now - timedelta(hours=2, minutes=45)  # MTTA = 15 mins
        )
        db.add_all([a1, a2])
        db.commit()

        # Seed Response Action
        resp1 = ResponseAction(
            alert_id=a1.id,
            device_id=dev2.id,
            action_type=ResponseActionType.ISOLATE,
            status=ResponseActionStatus.SUCCESS,
            initiated_by="AUTOMATIC",
            started_at=now - timedelta(minutes=40),
            completed_at=now - timedelta(minutes=30)  # MTTR = 15 mins (45m created to 30m completed)
        )
        db.add(resp1)
        db.commit()

        # Seed Telemetry Streams (USB, Network, Process, TelemetryLog)
        usb_e = USBEvent(
            device_id=dev1.id,
            event_type=USBEventType.INSERT,
            drive_letter="E:",
            volume_label="SUSPICIOUS_DRIVE",
            detected_at=now - timedelta(hours=1)
        )
        net_c = NetworkConnection(
            device_id=dev2.id,
            pid=2048,
            process_name="nc.exe",
            local_ip="192.168.10.100",
            remote_ip="198.51.100.99",
            remote_port=443,
            protocol="TCP",
            created_at=now - timedelta(hours=2)
        )
        proc_l = ProcessAuditLog(
            device_id=dev1.id,
            pid=4096,
            process_name="powershell.exe",
            event_type=ProcessEventType.DETECTION_FOUND,
            timestamp=now - timedelta(hours=3)
        )
        t_log = UnifiedTelemetryLog(
            device_id=dev1.id,
            category=TelemetryCategoryEnum.SECURITY_EVENT,
            event_type="PROCESS_START",
            source="auditd",
            timestamp=now - timedelta(minutes=10)
        )
        db.add_all([usb_e, net_c, proc_l, t_log])
        db.commit()

        # ---------------------------------------------------------------------
        # 2. VALIDATE METRIC CALCULATIONS
        # ---------------------------------------------------------------------
        analytics_engine = AnalyticsEngine(db)
        metrics_calc = BusinessMetricsCalculator(db)

        top_kpis = metrics_calc.calculate_top_executive_metrics()
        assert top_kpis["total_endpoints"] >= 2
        assert top_kpis["total_incidents"] >= 2
        assert top_kpis["critical_incidents"] >= 1
        assert top_kpis["responses_executed"] >= 1
        assert top_kpis["average_response_time_minutes"] >= 0.0

        resp_perf = metrics_calc.calculate_response_time_metrics(timeframe_days=7)
        assert resp_perf["mtta_sla_compliance_percent"] >= 0.0
        assert resp_perf["mttr_sla_compliance_percent"] >= 0.0

        posture = metrics_calc.calculate_security_posture_overview(timeframe_days=7)
        assert posture["total_monitored_endpoints"] >= 2
        assert posture["isolated_endpoints"] >= 1

        # ---------------------------------------------------------------------
        # 3. VALIDATE RISK SCORE CALCULATIONS & CONTRIBUTING FACTORS
        # ---------------------------------------------------------------------
        risk_scores = metrics_calc.calculate_endpoint_risk_scores(timeframe_days=7)
        assert len(risk_scores) >= 2

        db_srv_risk = next(r for r in risk_scores if r["hostname"] == dev_host2)
        assert db_srv_risk["risk_score"] >= 80.0
        assert db_srv_risk["risk_level"] in ["HIGH RISK", "CRITICAL RISK"]
        assert len(db_srv_risk["contributing_factors"]) > 0
        assert len(db_srv_risk["recommended_actions"]) > 0

        # Verify Ransomware & Isolation signals
        signals = [cf["signal"] for cf in db_srv_risk["contributing_factors"]]
        assert "Critical Severity Alert" in signals or "Ransomware Behavior" in signals or "Network Isolation Penalty" in signals

        # ---------------------------------------------------------------------
        # 4. VALIDATE MULTI-STREAM TREND GENERATION
        # ---------------------------------------------------------------------
        trend_analyzer = TrendAnalyzer(db)
        for tf in ["24h", "7d", "30d"]:
            trends = trend_analyzer.get_multi_stream_trends(timeframe=tf)
            assert "series" in trends
            assert "combined_buckets" in trends
            assert len(trends["series"]["threats_per_day"]) > 0
            assert len(trends["series"]["alerts_per_day"]) > 0
            assert len(trends["series"]["endpoint_activity"]) > 0
            assert len(trends["series"]["usb_insertions"]) > 0
            assert len(trends["series"]["network_detections"]) > 0
            assert len(trends["series"]["process_detections"]) > 0

        # Custom range trend validation
        custom_trends = trend_analyzer.get_multi_stream_trends(
            timeframe="custom",
            start_date=now - timedelta(days=5),
            end_date=now
        )
        assert custom_trends["timeframe"] == "custom"
        assert len(custom_trends["combined_buckets"]) == 6

        # ---------------------------------------------------------------------
        # 5. VALIDATE MITRE ATT&CK HEATMAP & COVERAGE
        # ---------------------------------------------------------------------
        mitre_mapper = MitreMapper(db)
        matrix = mitre_mapper.get_mitre_matrix_heatmap(timeframe_days=7)
        assert matrix["tactic_coverage_percent"] > 0.0
        assert len(matrix["matrix_columns"]) == 12
        assert len(matrix["top_tactics"]) > 0
        assert len(matrix["technique_frequency"]) > 0

        # Verify heat level calculation
        has_active_cell = False
        for col in matrix["matrix_columns"]:
            for cell in col["techniques"]:
                if cell["detection_count"] > 0:
                    assert cell["heat_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                    has_active_cell = True
        assert has_active_cell is True

        # ---------------------------------------------------------------------
        # 6. VALIDATE REPORT GENERATION & EXPORT FORMATS (PDF, CSV, JSON)
        # ---------------------------------------------------------------------
        reporter = ExecutiveReporter(db)

        # Executive Report JSON
        exec_json = reporter.generate_executive_summary_report(timeframe_days=7)
        assert exec_json["report_type"] == "EXECUTIVE_REPORT"
        assert "executive_summary" in exec_json
        assert "kpis" in exec_json

        # Technical Report JSON
        tech_json = reporter.generate_technical_report(timeframe_days=7)
        assert tech_json["report_type"] == "TECHNICAL_REPORT"
        assert len(tech_json["full_incident_list"]) >= 2
        assert len(tech_json["indicators"]) >= 1
        assert len(tech_json["response_actions"]) >= 1

        # PDF Report Bytes Generation
        exec_pdf_bytes = reporter.export_report_pdf(report_type="executive", timeframe_days=7)
        assert len(exec_pdf_bytes) > 500
        assert exec_pdf_bytes.startswith(b"%PDF")

        tech_pdf_bytes = reporter.export_report_pdf(report_type="technical", timeframe_days=7)
        assert len(tech_pdf_bytes) > 500
        assert tech_pdf_bytes.startswith(b"%PDF")

        # CSV Data Export Streams
        for ds in ["incidents", "endpoints", "mitre", "technical_iocs", "technical_responses"]:
            csv_text = reporter.export_dataset_to_csv(dataset_type=ds, timeframe_days=7)
            assert len(csv_text) > 0
            assert "," in csv_text

        # ---------------------------------------------------------------------
        # 7. VALIDATE API DASHBOARD ENDPOINTS & SCHEDULED REPORTS
        # ---------------------------------------------------------------------
        # API GET /analytics/dashboard
        res_dash = client.get("/api/v1/analytics/dashboard?timeframe_days=7", headers=headers)
        assert res_dash.status_code == 200
        dash_payload = res_dash.json()
        assert "top_metrics" in dash_payload
        assert "posture" in dash_payload

        # API GET /analytics/trends/charts
        res_charts = client.get("/api/v1/analytics/trends/charts?timeframe=7d", headers=headers)
        assert res_charts.status_code == 200
        assert "series" in res_charts.json()

        # API GET /analytics/mitre-matrix
        res_matrix = client.get("/api/v1/analytics/mitre-matrix?timeframe_days=7", headers=headers)
        assert res_matrix.status_code == 200
        assert len(res_matrix.json()["matrix_columns"]) == 12

        # API GET /analytics/report/pdf
        res_pdf_api = client.get("/api/v1/analytics/report/pdf?report_type=executive&timeframe_days=7", headers=headers)
        assert res_pdf_api.status_code == 200
        assert "application/pdf" in res_pdf_api.headers["content-type"]

        # API Scheduled Reports Workflow
        sched_create = client.post(
            "/api/v1/scheduled-reports",
            headers=headers,
            json={
                "title": "E2E Phase 8 Scheduled Report",
                "report_type": "EXECUTIVE",
                "frequency": "WEEKLY",
                "timeframe_days": 7,
                "export_format": "PDF",
                "recipients": ["ciso@sentinelx.io"]
            }
        )
        assert sched_create.status_code == 201
        cfg_id = sched_create.json()["id"]

        sched_run = client.post(f"/api/v1/scheduled-reports/{cfg_id}/run-now", headers=headers)
        assert sched_run.status_code == 200
        assert sched_run.json()["executed_at"] is not None

        sched_del = client.delete(f"/api/v1/scheduled-reports/{cfg_id}", headers=headers)
        assert sched_del.status_code == 204

    finally:
        db.close()
