"""
Phase 8 — Complete Fleet Management Master Integration & E2E Validation Suite

Validates:
1. Agent registration
2. Offline detection
3. Health monitoring
4. Remote commands
5. Bulk operations
6. Diagnostics
7. Version tracking & Upgrade Framework
8. Dashboard rendering data contract
"""

import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, HealthStatus, CommandStatus, OSType
from app.models.agent_command import AgentCommand, AgentCommandType, AgentCommandStatus
from app.models.agent_upgrade import AgentUpgradeRecord, AgentUpgradeStatus, RollbackStatus
from app.schemas.device import DeviceCreate, AgentHealthReportRequest
from app.schemas.agent_command import AgentCommandAcknowledgeRequest
from app.services import (
    fleet_service, device_service, agent_health_service,
    agent_command_service, agent_upgrade_service
)

client = TestClient(app)


def test_e2e_fleet_management_phase8_validation():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)

        # ------------------------------------------------------------------
        # 1. Agent Registration Validation
        # ------------------------------------------------------------------
        dev_in = DeviceCreate(
            hostname="phase8-e2e-node",
            ip_address="192.168.1.150",
            mac_address="DE:AD:BE:EF:00:01",
            os_type=OSType.LINUX,
            os_version="Ubuntu 22.04 LTS",
            agent_version="1.0.0",
            policy_version=1,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            last_command_status=CommandStatus.NONE
        )
        device = device_service.register_device(db_session, dev_in)
        assert device.id is not None
        assert device.hostname == "phase8-e2e-node"
        assert device.status == DeviceStatus.ONLINE

        # ------------------------------------------------------------------
        # 2. Offline Detection Validation
        # ------------------------------------------------------------------
        stale_dev = Device(
            hostname="stale-heartbeat-node-phase8",
            os_type=OSType.WINDOWS,
            status=DeviceStatus.ONLINE,
            health_status=HealthStatus.HEALTHY,
            last_heartbeat=datetime.now(timezone.utc) - timedelta(seconds=400) # > 300s timeout
        )
        db_session.add(stale_dev)
        db_session.commit()
        db_session.refresh(stale_dev)

        alerts = agent_health_service.evaluate_device_health(db_session, stale_dev)
        assert len(alerts) >= 1
        assert stale_dev.status == DeviceStatus.OFFLINE
        assert stale_dev.health_status == HealthStatus.UNHEALTHY

        # ------------------------------------------------------------------
        # 3. Health Monitoring Telemetry & Alert Generation Validation
        # ------------------------------------------------------------------
        health_report = AgentHealthReportRequest(
            device_id=device.id,
            cpu_usage_percent=92.0,
            ram_usage_mb=16000.0,
            ram_usage_percent=94.0,
            disk_usage_percent=80.0,
            agent_uptime_seconds=36000,
            service_status="RUNNING"
        )
        updated_dev = agent_health_service.ingest_agent_health_report(db_session, health_report)
        assert updated_dev.cpu_usage_percent == 92.0
        assert updated_dev.health_status == HealthStatus.WARNING

        # ------------------------------------------------------------------
        # 4. Remote Commands Queue, Dispatch, & Acknowledge Validation
        # ------------------------------------------------------------------
        auth_resp = client.post("/api/v1/auth/login/json", json={
            "username_or_email": "admin",
            "password": "AdminPassword123!"
        })
        token = auth_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        cmd_res = client.post("/api/v1/fleet/commands", json={
            "device_id": str(device.id),
            "command_type": "START_SCAN",
            "payload": {"scan_path": "/home"}
        }, headers=headers)
        assert cmd_res.status_code == 201
        cmd_id = cmd_res.json()["id"]

        # Dispatch
        poll_res = client.get(f"/api/v1/fleet/commands/pending/{device.id}")
        assert poll_res.status_code == 200
        assert poll_res.json()[0]["status"] == "DISPATCHED"

        # Acknowledge
        ack_res = client.post("/api/v1/fleet/commands/acknowledge", json={
            "command_id": cmd_id,
            "status": "SUCCESS",
            "result_output": "Scan completed: 0 threats found."
        })
        assert ack_res.status_code == 200
        assert ack_res.json()["status"] == "SUCCESS"

        # ------------------------------------------------------------------
        # 5. Bulk Operations & CSV Export Validation
        # ------------------------------------------------------------------
        batch_res = client.post("/api/v1/fleet/commands/batch", json={
            "device_ids": [str(device.id), str(stale_dev.id)],
            "command_type": "REFRESH_POLICY",
            "payload": {"policy_version": 3}
        }, headers=headers)
        assert batch_res.status_code == 201
        assert len(batch_res.json()) == 2

        export_res = client.get("/api/v1/fleet/export")
        assert export_res.status_code == 200
        assert "text/csv" in export_res.headers["content-type"]
        assert "phase8-e2e-node" in export_res.text

        # ------------------------------------------------------------------
        # 6. Diagnostics Package Validation
        # ------------------------------------------------------------------
        diag_res = client.get(f"/api/v1/fleet/devices/{device.id}/diagnostics")
        assert diag_res.status_code == 200
        diag_data = diag_res.json()
        assert diag_data["hostname"] == "phase8-e2e-node"
        assert "installed_collectors" in diag_data
        assert "agent_logs" in diag_data

        # ------------------------------------------------------------------
        # 7. Version Tracking & Upgrade Framework Validation
        # ------------------------------------------------------------------
        up_res = client.post("/api/v1/fleet/upgrade/trigger", json={
            "device_ids": [str(device.id)],
            "target_version": "1.2.0"
        }, headers=headers)
        assert up_res.status_code == 201
        up_id = up_res.json()[0]["id"]

        # Step progression
        for expected_status in ["DOWNLOADING", "INSTALLING", "RESTARTING", "SUCCESS"]:
            step_res = client.post(f"/api/v1/fleet/upgrade/step?upgrade_id={up_id}")
            assert step_res.status_code == 200
            assert step_res.json()["status"] == expected_status

        db_session.refresh(device)
        assert device.agent_version == "1.2.0"

        # ------------------------------------------------------------------
        # 8. Dashboard Summary Rendering Contract Validation
        # ------------------------------------------------------------------
        metrics_res = client.get("/api/v1/fleet/metrics")
        assert metrics_res.status_code == 200
        metrics = metrics_res.json()
        assert metrics["total_agents"] >= 2
        assert metrics["offline"] >= 1

        summary_res = client.get("/api/v1/fleet/summary")
        assert summary_res.status_code == 200
        assert "metrics" in summary_res.json()
        assert "recent_devices" in summary_res.json()

    finally:
        db_session.close()
