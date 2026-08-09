"""
Unit Tests for Phase 1 - Analytics Engine
Tests TelemetryAggregator, BusinessMetricsCalculator, TrendAnalyzer, MitreMapper, ExecutiveReporter, and AnalyticsEngine facade.
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.analytics.engine import AnalyticsEngine
from app.analytics.mitre import MitreMapper, MITRE_ATTACK_MAP
from app.analytics.aggregation import TelemetryAggregator
from app.analytics.metrics import BusinessMetricsCalculator
from app.analytics.trends import TrendAnalyzer
from app.analytics.reporting import ExecutiveReporter


def test_analytics_engine_full_lifecycle():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Create Devices
        dev1 = Device(
            hostname="exec-workstation-01",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE,
            ip_address="192.168.1.100"
        )
        dev2 = Device(
            hostname="db-server-02",
            os_type=OSType.LINUX,
            status=DeviceStatus.ISOLATED,
            ip_address="192.168.1.200"
        )
        db.add_all([dev1, dev2])
        db.commit()

        # 2. Create Threat
        threat1 = Threat(
            threat_type=ThreatType.KNOWN_MALWARE,
            severity=ThreatSeverity.CRITICAL,
            rule_name="Mass File Encryption Pattern Detected",
            description="Suspicious process modified 50 files in short window.",
            status=ThreatStatus.NEW
        )
        threat2 = Threat(
            threat_type=ThreatType.SUSPICIOUS_POWERSHELL,
            severity=ThreatSeverity.HIGH,
            rule_name="Encoded PowerShell Command",
            description="PowerShell executed with -EncodedCommand flag.",
            status=ThreatStatus.RESOLVED
        )
        db.add_all([threat1, threat2])
        db.commit()

        # 3. Create Alerts
        now = datetime.now(timezone.utc)
        alert1 = Alert(
            threat_id=threat1.id,
            device_id=dev2.id,
            title="Ransomware Behavior Triggered",
            message="Possible ransomware on db-server-02",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.UNREAD,
            created_at=now - timedelta(minutes=30)
        )
        alert2 = Alert(
            threat_id=threat2.id,
            device_id=dev1.id,
            title="Encoded PowerShell Detected",
            message="Suspicious PowerShell command on exec-workstation-01",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.ACKNOWLEDGED,
            created_at=now - timedelta(hours=2),
            acknowledged_at=now - timedelta(hours=1, minutes=45)
        )
        db.add_all([alert1, alert2])
        db.commit()

        # 4. Create Response Action
        action1 = ResponseAction(
            alert_id=alert1.id,
            device_id=dev2.id,
            action_type=ResponseActionType.ISOLATE,
            status=ResponseActionStatus.SUCCESS,
            initiated_by="AUTOMATIC",
            started_at=now - timedelta(minutes=25),
            completed_at=now - timedelta(minutes=20)
        )
        db.add(action1)
        db.commit()

        # Instantiate AnalyticsEngine
        analytics_engine = AnalyticsEngine(db)

        # Test MitreMapper
        mitre_res = analytics_engine.get_mitre_attack_analytics(timeframe_days=7)
        assert mitre_res["total_observed_threats"] >= 2
        assert len(mitre_res["tactics_breakdown"]) > 0
        assert len(mitre_res["top_techniques"]) > 0

        # Test Mitre Type Lookup directly
        mapper = MitreMapper(db)
        r_map = mapper.get_mapping_for_type("RANSOMWARE_BEHAVIOR")
        assert r_map["tactic_id"] == "TA0040"
        assert r_map["technique_id"] == "T1486"

        # Test Endpoint Risk Analytics
        risk_scores = analytics_engine.get_endpoint_risk_analytics(timeframe_days=7)
        assert len(risk_scores) >= 2
        top_dev = risk_scores[0]
        assert top_dev["risk_score"] >= 0
        assert top_dev["risk_level"] in ["LOW RISK", "MEDIUM RISK", "HIGH RISK", "CRITICAL RISK"]

        # Test Incident Trends & Velocity
        trends = analytics_engine.get_incident_trends(days=7)
        assert len(trends["daily_trends"]) == 7
        assert "velocity" in trends
        assert trends["velocity"]["overall_direction"] in ["INCREASING", "DECREASING", "STABLE"]

        # Test Response Performance (MTTA / MTTR)
        response_perf = analytics_engine.get_response_performance(timeframe_days=7)
        assert response_perf["acknowledged_count"] >= 1
        assert response_perf["responded_count"] >= 1

        # Test Executive Dashboard Summary
        summary = analytics_engine.get_executive_dashboard_summary(timeframe_days=7)
        assert "posture" in summary
        assert summary["posture"]["total_monitored_endpoints"] >= 2
        assert summary["alerts_by_severity"]["CRITICAL"] >= 1
        assert summary["alerts_by_severity"]["HIGH"] >= 1

        # Test Executive Report Payload
        report = analytics_engine.generate_executive_report(timeframe_days=7)
        assert "executive_summary" in report
        assert "kpis" in report
        assert report["executive_summary"]["overall_risk_status"] in ["ELEVATED RISK", "MODERATE RISK", "LOW RISK"]

        # Test CSV Export
        csv_incidents = analytics_engine.export_analytics_csv("incidents", timeframe_days=7)
        assert "Date,Total Alerts,Critical,High,Medium,Low" in csv_incidents
        csv_endpoints = analytics_engine.export_analytics_csv("endpoints", timeframe_days=7)
        assert "Device ID,Hostname,IP Address" in csv_endpoints
        csv_mitre = analytics_engine.export_analytics_csv("mitre", timeframe_days=7)
        assert "Technique ID,Technique Name" in csv_mitre

    finally:
        db.close()
