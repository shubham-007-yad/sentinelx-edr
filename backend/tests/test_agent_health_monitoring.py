import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, HealthStatus, CommandStatus, OSType
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.threat import Threat, ThreatType
from app.services import agent_health_service, device_service
from app.schemas.device import DeviceCreate, AgentHealthReportRequest

client = TestClient(app)


def test_agent_health_ingestion_and_resource_alert():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev_in = DeviceCreate(
            hostname="health-node-1",
            ip_address="192.168.1.100",
            os_type=OSType.LINUX,
            agent_version="1.0.0",
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY
        )
        dev = device_service.register_device(db_session, dev_in)

        report = AgentHealthReportRequest(
            device_id=dev.id,
            cpu_usage_percent=95.0,
            ram_usage_mb=14200.0,
            ram_usage_percent=92.5,
            disk_usage_percent=45.0,
            agent_uptime_seconds=86400,
            service_status="RUNNING",
            last_telemetry_upload=datetime.now(timezone.utc),
            last_policy_sync=datetime.now(timezone.utc)
        )
        updated_dev = agent_health_service.ingest_agent_health_report(db_session, report)

        assert updated_dev.cpu_usage_percent == 95.0
        assert updated_dev.ram_usage_percent == 92.5
        assert updated_dev.health_status == HealthStatus.WARNING

        alert = db_session.query(Alert).filter(Alert.device_id == dev.id, Alert.title.like("%High Resource Usage%")).first()
        assert alert is not None
        assert alert.severity == AlertSeverity.HIGH
    finally:
        db_session.close()


def test_agent_stopped_health_alert():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev = Device(
            hostname="stopped-service-node",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            service_status="RUNNING",
            last_heartbeat=datetime.now(timezone.utc)
        )
        db_session.add(dev)
        db_session.commit()
        db_session.refresh(dev)

        report = AgentHealthReportRequest(
            device_id=dev.id,
            cpu_usage_percent=5.0,
            ram_usage_percent=20.0,
            disk_usage_percent=30.0,
            agent_uptime_seconds=100,
            service_status="STOPPED",
            last_telemetry_upload=datetime.now(timezone.utc),
            last_policy_sync=datetime.now(timezone.utc)
        )
        updated_dev = agent_health_service.ingest_agent_health_report(db_session, report)
        assert updated_dev.health_status == HealthStatus.UNHEALTHY

        alert = db_session.query(Alert).filter(Alert.device_id == dev.id, Alert.title.like("%Agent Service Stopped%")).first()
        assert alert is not None
        assert alert.severity == AlertSeverity.CRITICAL
    finally:
        db_session.close()


def test_no_heartbeat_timeout_alert():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        stale_time = datetime.now(timezone.utc) - timedelta(seconds=400)
        dev = Device(
            hostname="stale-heartbeat-node",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            service_status="RUNNING",
            last_heartbeat=stale_time,
            last_policy_sync=datetime.now(timezone.utc)
        )
        db_session.add(dev)
        db_session.commit()
        db_session.refresh(dev)

        alerts = agent_health_service.evaluate_device_health(db_session, dev)
        assert len(alerts) >= 1
        assert dev.status == DeviceStatus.OFFLINE
        assert dev.health_status == HealthStatus.UNHEALTHY

        hb_alert = db_session.query(Alert).filter(Alert.device_id == dev.id, Alert.title.like("%No Heartbeat Received%")).first()
        assert hb_alert is not None
        assert hb_alert.severity == AlertSeverity.HIGH
    finally:
        db_session.close()


def test_policy_sync_failure_alert():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        old_sync_time = datetime.now(timezone.utc) - timedelta(hours=30)
        dev = Device(
            hostname="stale-policy-sync-node",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            service_status="RUNNING",
            last_heartbeat=datetime.now(timezone.utc),
            last_policy_sync=old_sync_time
        )
        db_session.add(dev)
        db_session.commit()
        db_session.refresh(dev)

        alerts = agent_health_service.evaluate_device_health(db_session, dev)
        assert len(alerts) >= 1
        assert dev.health_status == HealthStatus.WARNING

        policy_alert = db_session.query(Alert).filter(Alert.device_id == dev.id, Alert.title.like("%Policy Sync Failure%")).first()
        assert policy_alert is not None
        assert policy_alert.severity == AlertSeverity.MEDIUM
    finally:
        db_session.close()


def test_fleet_health_api_endpoints():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev_in = DeviceCreate(
            hostname="api-health-node",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY
        )
        dev = device_service.register_device(db_session, dev_in)

        report_payload = {
            "device_id": str(dev.id),
            "cpu_usage_percent": 45.0,
            "ram_usage_mb": 2048.0,
            "ram_usage_percent": 50.0,
            "disk_usage_percent": 60.0,
            "agent_uptime_seconds": 3600,
            "service_status": "RUNNING"
        }
        response = client.post("/api/v1/fleet/health/report", json=report_payload)
        assert response.status_code == 200
        data = response.json()
        assert data["cpu_usage_percent"] == 45.0
        assert data["health_status"] == "HEALTHY"

        eval_resp = client.post("/api/v1/fleet/health/evaluate")
        assert eval_resp.status_code == 200
        eval_data = eval_resp.json()
        assert "evaluated_devices" in eval_data
        assert "health_alerts_generated" in eval_data
    finally:
        db_session.close()
