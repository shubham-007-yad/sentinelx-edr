import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, HealthStatus, OSType
from app.models.agent_upgrade import AgentUpgradeRecord, AgentUpgradeStatus, RollbackStatus
from app.services import agent_upgrade_service, device_service, user_service
from app.schemas.device import DeviceCreate
from app.schemas.user import UserCreate
from app.models.user import UserRole

client = TestClient(app)


def test_agent_upgrade_service_workflow():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev_in = DeviceCreate(
            hostname="upgrade-service-node",
            os_type=OSType.LINUX,
            agent_version="1.0.0",
            status=DeviceStatus.ONLINE
        )
        dev = device_service.register_device(db_session, dev_in)

        # 1. Trigger Upgrade (v1.0.0 -> v1.2.0)
        records = agent_upgrade_service.trigger_agent_upgrades(
            db=db_session,
            device_ids=[dev.id],
            target_version="1.2.0"
        )
        assert len(records) == 1
        rec = records[0]
        assert rec.current_version == "1.0.0"
        assert rec.target_version == "1.2.0"
        assert rec.status == AgentUpgradeStatus.AVAILABLE
        assert rec.progress_percent == 0

        # 2. Advance Step 1: AVAILABLE -> DOWNLOADING (25%)
        rec_step1 = agent_upgrade_service.advance_upgrade_simulation_step(db_session, rec.id)
        assert rec_step1.status == AgentUpgradeStatus.DOWNLOADING
        assert rec_step1.progress_percent == 25
        assert "Downloading" in rec_step1.logs

        # 3. Advance Step 2: DOWNLOADING -> INSTALLING (65%)
        rec_step2 = agent_upgrade_service.advance_upgrade_simulation_step(db_session, rec.id)
        assert rec_step2.status == AgentUpgradeStatus.INSTALLING
        assert rec_step2.progress_percent == 65

        # 4. Advance Step 3: INSTALLING -> RESTARTING (90%)
        rec_step3 = agent_upgrade_service.advance_upgrade_simulation_step(db_session, rec.id)
        assert rec_step3.status == AgentUpgradeStatus.RESTARTING
        assert rec_step3.progress_percent == 90

        # 5. Advance Step 4: RESTARTING -> SUCCESS (100%)
        rec_step4 = agent_upgrade_service.advance_upgrade_simulation_step(db_session, rec.id)
        assert rec_step4.status == AgentUpgradeStatus.SUCCESS
        assert rec_step4.progress_percent == 100
        assert dev.agent_version == "1.2.0"

        # 6. Test Rollback to v1.0.0
        rec_rollback = agent_upgrade_service.rollback_agent_upgrade(db_session, rec.id, target_rollback_version="1.0.0")
        assert rec_rollback.status == AgentUpgradeStatus.ROLLED_BACK
        assert rec_rollback.rollback_status == RollbackStatus.SUCCESSFUL
        assert dev.agent_version == "1.0.0"
    finally:
        db_session.close()


def test_agent_upgrade_api_endpoints():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev_in = DeviceCreate(
            hostname="upgrade-api-node",
            os_type=OSType.WINDOWS,
            agent_version="1.0.0",
            status=DeviceStatus.ONLINE
        )
        dev = device_service.register_device(db_session, dev_in)

        # Obtain auth token for admin
        auth_resp = client.post("/api/v1/auth/login/json", json={
            "username_or_email": "admin",
            "password": "AdminPassword123!"
        })
        token = auth_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. POST /api/v1/fleet/upgrade/trigger
        trigger_payload = {
            "device_ids": [str(dev.id)],
            "target_version": "1.2.0"
        }
        res_trigger = client.post("/api/v1/fleet/upgrade/trigger", json=trigger_payload, headers=headers)
        assert res_trigger.status_code == 201
        upgrades = res_trigger.json()
        assert len(upgrades) == 1
        up_id = upgrades[0]["id"]
        assert upgrades[0]["target_version"] == "1.2.0"

        # 2. POST /api/v1/fleet/upgrade/step
        res_step = client.post(f"/api/v1/fleet/upgrade/step?upgrade_id={up_id}")
        assert res_step.status_code == 200
        step_data = res_step.json()
        assert step_data["status"] == "DOWNLOADING"
        assert step_data["progress_percent"] == 25

        # 3. POST /api/v1/fleet/upgrade/rollback
        res_rb = client.post("/api/v1/fleet/upgrade/rollback", json={"upgrade_id": up_id, "target_rollback_version": "1.0.0"}, headers=headers)
        assert res_rb.status_code == 200
        rb_data = res_rb.json()
        assert rb_data["status"] == "ROLLED_BACK"
        assert rb_data["rollback_status"] == "SUCCESSFUL"

        # 4. GET /api/v1/fleet/upgrade/history
        res_hist = client.get(f"/api/v1/fleet/upgrade/history?device_id={dev.id}")
        assert res_hist.status_code == 200
        history = res_hist.json()
        assert len(history) >= 1
        assert history[0]["id"] == up_id
    finally:
        db_session.close()
