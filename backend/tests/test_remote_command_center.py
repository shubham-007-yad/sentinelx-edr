import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, CommandStatus, OSType
from app.models.user import User, UserRole
from app.models.agent_command import AgentCommand, AgentCommandType, AgentCommandStatus, AgentCommandAuditLog
from app.services import agent_command_service, device_service, user_service
from app.schemas.device import DeviceCreate
from app.schemas.agent_command import AgentCommandCreate, AgentCommandAcknowledgeRequest
from app.schemas.user import UserCreate

client = TestClient(app)


def test_command_lifecycle_queue_dispatch_acknowledge():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev_in = DeviceCreate(
            hostname="cmd-target-node",
            ip_address="192.168.1.200",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE
        )
        dev = device_service.register_device(db_session, dev_in)

        admin = user_service.get_user_by_username(db_session, "admin")
        if not admin:
            admin = user_service.create_user(
                db_session,
                user_in=UserCreate(
                    email="admin-cmd@sentinelx.io",
                    username="admin",
                    password="AdminPassword123!",
                    role=UserRole.ADMIN
                )
            )

        # 1. Queue command
        cmd = agent_command_service.queue_command(
            db=db_session,
            device_id=dev.id,
            command_type=AgentCommandType.START_SCAN,
            payload={"scan_path": "/var/log", "deep_scan": True},
            issuer=admin
        )
        assert cmd.status == AgentCommandStatus.PENDING
        assert cmd.command_type == AgentCommandType.START_SCAN
        assert dev.last_command_status == CommandStatus.PENDING

        # 2. Agent fetches pending commands (Dispatch stage)
        pending_list = agent_command_service.get_pending_commands_for_device(db_session, dev.id)
        assert len(pending_list) == 1
        assert pending_list[0].status == AgentCommandStatus.DISPATCHED
        assert dev.last_command_status == CommandStatus.DISPATCHED

        # 3. Agent acknowledges command completion (Acknowledge stage)
        ack_in = AgentCommandAcknowledgeRequest(
            command_id=cmd.id,
            status=AgentCommandStatus.SUCCESS,
            result_output="Scan completed successfully. 0 threats found.",
            execution_duration_ms=450
        )
        ack_cmd = agent_command_service.acknowledge_command(db_session, ack_in)
        assert ack_cmd.status == AgentCommandStatus.SUCCESS
        assert ack_cmd.result_output == "Scan completed successfully. 0 threats found."
        assert dev.last_command_status == CommandStatus.EXECUTED

        # 4. Audit Log verification
        audit_logs = agent_command_service.get_command_audit_logs(db_session, device_id=dev.id)
        assert len(audit_logs) >= 2
        assert audit_logs[0].command_type == "START_SCAN"
    finally:
        db_session.close()


def test_command_center_api_flow():
    db_session: Session = SessionLocal()
    try:
        init_db(db_session)
        dev_in = DeviceCreate(
            hostname="api-cmd-node",
            os_type=OSType.WINDOWS,
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

        # Test POST /api/v1/fleet/commands (Queue command)
        cmd_payload = {
            "device_id": str(dev.id),
            "command_type": "COLLECT_DIAGNOSTICS",
            "payload": {"include_syslog": True}
        }
        response = client.post("/api/v1/fleet/commands", json=cmd_payload, headers=headers)
        assert response.status_code == 201
        cmd_data = response.json()
        cmd_id = cmd_data["id"]
        assert cmd_data["command_type"] == "COLLECT_DIAGNOSTICS"
        assert cmd_data["status"] == "PENDING"

        # Test GET /api/v1/fleet/commands/pending/{device_id}
        poll_resp = client.get(f"/api/v1/fleet/commands/pending/{dev.id}")
        assert poll_resp.status_code == 200
        pending_cmds = poll_resp.json()
        assert len(pending_cmds) == 1
        assert pending_cmds[0]["status"] == "DISPATCHED"

        # Test POST /api/v1/fleet/commands/acknowledge
        ack_payload = {
            "command_id": cmd_id,
            "status": "SUCCESS",
            "result_output": "Diagnostics zip bundle generated: /tmp/diag_host_1.zip",
            "execution_duration_ms": 1200
        }
        ack_resp = client.post("/api/v1/fleet/commands/acknowledge", json=ack_payload)
        assert ack_resp.status_code == 200
        ack_data = ack_resp.json()
        assert ack_data["status"] == "SUCCESS"

        # Test GET /api/v1/fleet/commands/history
        hist_resp = client.get(f"/api/v1/fleet/commands/history?device_id={dev.id}")
        assert hist_resp.status_code == 200
        history = hist_resp.json()
        assert len(history) >= 1
        assert history[0]["command_type"] == "COLLECT_DIAGNOSTICS"

        # Test GET /api/v1/fleet/commands/audit-logs
        audit_resp = client.get(f"/api/v1/fleet/commands/audit-logs?device_id={dev.id}")
        assert audit_resp.status_code == 200
        audits = audit_resp.json()
        assert len(audits) >= 1
        assert audits[0]["issuer_username"] == "admin"
    finally:
        db_session.close()
