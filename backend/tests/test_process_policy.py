import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.main import app
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import ProcessPolicyConfigSchema
from app.services.policy_service import PolicyService, DEFAULT_PROCESS_CONFIG
from agent.collectors.live_process_monitor import ProcessMonitor


client = TestClient(app)


def _reset_policies(db: Session):
    db.query(SecurityPolicy).filter(SecurityPolicy.category == PolicyCategory.PROCESS).delete()
    db.commit()


def test_process_policy_service_defaults():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
        config = PolicyService.get_active_process_policy(db)
        assert config["monitor_powershell"] is True
        assert config["monitor_lolbins"] is True
        assert config["cpu_threshold_percent"] == 80.0
        assert config["memory_threshold_mb"] == 500.0
        assert "mimikatz.exe" in config["blocklisted_processes"]
    finally:
        db.close()


def test_process_policy_api_endpoints():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
    finally:
        db.close()

    # 1. GET initial process policy
    response = client.get("/api/v1/processes/policy")
    assert response.status_code == 200
    data = response.json()
    assert data["monitor_powershell"] is True
    assert data["cpu_threshold_percent"] == 80.0

    # 2. PUT updated process policy
    updated_payload = {
        "monitor_powershell": True,
        "monitor_lolbins": False,
        "cpu_threshold_percent": 60.0,
        "memory_threshold_mb": 250.0,
        "allowed_processes": ["chrome.exe"],
        "blocklisted_processes": ["mimikatz.exe", "hack.exe"],
        "auto_kill_blocklisted": True,
        "parent_child_rules_enabled": True
    }

    put_resp = client.put("/api/v1/processes/policy", json=updated_payload)
    assert put_resp.status_code == 200
    res_data = put_resp.json()
    assert res_data["cpu_threshold_percent"] == 60.0
    assert res_data["monitor_lolbins"] is False
    assert res_data["auto_kill_blocklisted"] is True
    assert "hack.exe" in res_data["blocklisted_processes"]

    # 3. GET verify persistence
    get_resp2 = client.get("/api/v1/processes/policy")
    assert get_resp2.status_code == 200
    assert get_resp2.json()["cpu_threshold_percent"] == 60.0


def test_process_monitor_policy_enforcement():
    custom_policy = {
        "monitor_powershell": False,
        "monitor_lolbins": True,
        "cpu_threshold_percent": 10.0,
        "memory_threshold_mb": 1.0,
        "blocklisted_processes": ["test_blocked_bin.exe"],
        "auto_kill_blocklisted": False
    }

    monitor = ProcessMonitor(policy=custom_policy)
    
    # Inject mock process state into previous snapshot to simulate process creation
    monitor._previous_processes = {}
    
    diff = monitor.collect_and_diff()
    assert isinstance(diff["created"], list)
    assert isinstance(diff["blocklist_hits"], list)

    # Verify powershell process filtering
    for proc in diff["created"]:
        assert proc["name"].lower() not in {"powershell.exe", "pwsh.exe"}
