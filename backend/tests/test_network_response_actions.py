import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.threat import Threat, ThreatType, ThreatSeverity
from app.models.alert import Alert, AlertSeverity, AlertStatus

client = TestClient(app)


def test_network_five_response_actions_and_audit_logs():
    db = SessionLocal()
    try:
        # 1. Setup endpoint device
        device = Device(
            hostname="target-workstation-network",
            ip_address="192.168.1.110",
            mac_address="DE:AD:BE:EF:00:02",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE
        )
        db.add(device)
        db.commit()
        db.refresh(device)

        # 2. Setup Threat and Alert
        threat = Threat(
            threat_type=ThreatType.BLACK_LISTED_IP,
            severity=ThreatSeverity.HIGH,
            rule_name="NET-RULE-0002",
            description="Connection to known malicious C2 IP 185.220.101.5 (PID 4050, process nc)"
        )
        db.add(threat)
        db.commit()

        alert = Alert(
            threat_id=threat.id,
            device_id=device.id,
            title="Blacklisted C2 Connection",
            message="nc connected to 185.220.101.5:4444",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.UNREAD
        )
        db.add(alert)
        db.commit()

        # Action 1: BLOCK_IP
        payload_block = {
            "device_id": str(device.id),
            "alert_id": str(alert.id),
            "action_type": "BLOCK_IP",
            "initiated_by": "ANALYST",
            "parameters": {"remote_ip": "185.220.101.5", "remote_port": 4444}
        }
        res_block = client.post("/api/v1/responses/trigger", json=payload_block)
        assert res_block.status_code == 201, res_block.text
        action_block = res_block.json()
        assert action_block["status"] == "SUCCESS"

        # Verify BLOCK_IP Audit Log
        res_logs = client.get(f"/api/v1/responses/{action_block['id']}/audit-logs")
        assert res_logs.status_code == 200, res_logs.text
        logs = res_logs.json()
        assert len(logs) >= 1
        assert "BLOCK_IP" in logs[0]["message"]
        assert logs[0]["details"]["remote_ip"] == "185.220.101.5"

        # Action 2: TERMINATE_PROCESS (Kill Process)
        payload_kill = {
            "device_id": str(device.id),
            "alert_id": str(alert.id),
            "action_type": "TERMINATE_PROCESS",
            "initiated_by": "ANALYST",
            "parameters": {"pid": 4050, "process_name": "nc"}
        }
        res_kill = client.post("/api/v1/responses/trigger", json=payload_kill)
        assert res_kill.status_code == 201, res_kill.text
        action_kill = res_kill.json()
        assert action_kill["status"] == "SUCCESS"

        # Verify TERMINATE_PROCESS Audit Log
        res_kill_logs = client.get(f"/api/v1/responses/{action_kill['id']}/audit-logs")
        assert res_kill_logs.status_code == 200
        assert any("TERMINATE_PROCESS" in log["message"] for log in res_kill_logs.json())

        # Action 3: IGNORE (Dismiss Alert)
        payload_ignore = {
            "device_id": str(device.id),
            "alert_id": str(alert.id),
            "action_type": "IGNORE",
            "initiated_by": "ANALYST",
            "parameters": {"reason": "False positive verified by SOC"}
        }
        res_ignore = client.post("/api/v1/responses/trigger", json=payload_ignore)
        assert res_ignore.status_code == 201, res_ignore.text
        action_ignore = res_ignore.json()
        assert action_ignore["status"] == "SUCCESS"

        # Verify IGNORE Audit Log
        res_ignore_logs = client.get(f"/api/v1/responses/{action_ignore['id']}/audit-logs")
        assert res_ignore_logs.status_code == 200
        assert any("IGNORE" in log["message"] for log in res_ignore_logs.json())

        # Action 4: ADD_ALLOWLIST (Allowlist)
        payload_allow = {
            "device_id": str(device.id),
            "alert_id": str(alert.id),
            "action_type": "ADD_ALLOWLIST",
            "initiated_by": "ANALYST",
            "parameters": {"process_name": "nc", "allowlist_type": "PROCESS_IP"}
        }
        res_allow = client.post("/api/v1/responses/trigger", json=payload_allow)
        assert res_allow.status_code == 201, res_allow.text
        action_allow = res_allow.json()
        assert action_allow["status"] == "SUCCESS"

        # Verify ADD_ALLOWLIST Audit Log
        res_allow_logs = client.get(f"/api/v1/responses/{action_allow['id']}/audit-logs")
        assert res_allow_logs.status_code == 200
        assert any("ADD_ALLOWLIST" in log["message"] for log in res_allow_logs.json())

        # Action 5: INVESTIGATE
        payload_investigate = {
            "device_id": str(device.id),
            "alert_id": str(alert.id),
            "action_type": "INVESTIGATE",
            "initiated_by": "ANALYST",
            "parameters": {"investigation_session": "SOC-INCIDENT-9941"}
        }
        res_inv = client.post("/api/v1/responses/trigger", json=payload_investigate)
        assert res_inv.status_code == 201, res_inv.text
        action_inv = res_inv.json()
        assert action_inv["status"] == "SUCCESS"

        # Verify INVESTIGATE Audit Log
        res_inv_logs = client.get(f"/api/v1/responses/{action_inv['id']}/audit-logs")
        assert res_inv_logs.status_code == 200
        assert any("INVESTIGATE" in log["message"] for log in res_inv_logs.json())

    finally:
        db.close()
