import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.response_action import ResponseActionType, ResponseActionStatus
from app.services.response_service import (
    execute_response,
    get_audit_logs_by_action_id
)

client = TestClient(app)


def setup_db():
    Base.metadata.create_all(bind=engine)
    return SessionLocal()


def test_audit_trail_forensic_lifecycle():
    db = setup_db()
    try:
        # 1. Create target Device
        hostname = f"audit-node-{str(uuid.uuid4())[:8]}"
        device = Device(
            hostname=hostname,
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # 2. Execute Response Action
        action = execute_response(
            db=db,
            device_id=device.id,
            action_type=ResponseActionType.QUARANTINE,
            initiated_by="admin@sentinelx.io",
            user_role="ADMIN"
        )

        assert action.id is not None

        # 3. Retrieve Audit Trail via Service
        audit_logs = get_audit_logs_by_action_id(db, action.id)
        assert len(audit_logs) >= 2

        stages = [log.stage for log in audit_logs]
        assert "INITIATED" in stages
        assert "SUCCESS" in stages

        # Verify initiated log details
        init_log = audit_logs[0]
        assert init_log.stage == "INITIATED"
        assert init_log.actor == "admin@sentinelx.io"
        assert "initiated QUARANTINE action" in init_log.message

        # 4. Retrieve Audit Trail via API GET Endpoint
        api_res = client.get(f"/api/v1/responses/{action.id}/audit-logs")
        assert api_res.status_code == 200
        logs_data = api_res.json()
        assert len(logs_data) >= 2
        assert logs_data[0]["stage"] == "INITIATED"
        assert logs_data[-1]["stage"] == "SUCCESS"

    finally:
        db.close()
