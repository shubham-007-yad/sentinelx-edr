import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.main import app
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import NetworkPolicyConfigSchema
from app.services.policy_service import PolicyService, DEFAULT_NETWORK_CONFIG
from agent.collectors.network_collector import NetworkMonitor


client = TestClient(app)


def _reset_policies(db: Session):
    db.query(SecurityPolicy).filter(SecurityPolicy.category == PolicyCategory.NETWORK).delete()
    db.commit()


def test_network_policy_service_defaults():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
        config = PolicyService.get_active_network_policy(db)
        assert 4444 in config["blocked_ports"]
        assert "198.51.100.99" in config["blocklisted_ips"]
        assert config["monitor_external_connections"] is True
    finally:
        db.close()


def test_network_policy_api_endpoints():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
    finally:
        db.close()

    # 1. GET initial network policy
    response = client.get("/api/v1/network/policy")
    assert response.status_code == 200
    data = response.json()
    assert 4444 in data["blocked_ports"]

    # 2. PUT updated network policy
    updated_payload = {
        "allowed_ports": [80, 443],
        "blocked_ports": [4444, 9999],
        "allowlisted_ips": ["1.1.1.1"],
        "blocklisted_ips": ["203.0.113.50"],
        "monitor_external_connections": False,
        "beacon_interval_threshold_seconds": 30.0,
        "beacon_jitter_percent": 15.0,
        "auto_block_c2_connections": True
    }

    put_resp = client.put("/api/v1/network/policy", json=updated_payload)
    assert put_resp.status_code == 200
    res_data = put_resp.json()
    assert 9999 in res_data["blocked_ports"]
    assert "203.0.113.50" in res_data["blocklisted_ips"]
    assert res_data["auto_block_c2_connections"] is True

    # 3. GET verify persistence
    get_resp2 = client.get("/api/v1/network/policy")
    assert get_resp2.status_code == 200
    assert get_resp2.json()["auto_block_c2_connections"] is True


def test_network_monitor_policy_enforcement():
    custom_policy = {
        "blocked_ports": [8888],
        "blocklisted_ips": ["198.51.100.200"],
        "monitor_external_connections": True,
        "auto_block_c2_connections": False
    }

    monitor = NetworkMonitor(policy=custom_policy)
    
    # Verify IP classification helper
    assert monitor.is_private_ip("192.168.1.1") is True
    assert monitor.is_private_ip("10.0.0.5") is True
    assert monitor.is_private_ip("8.8.8.8") is False

    diff = monitor.collect_and_diff()
    assert isinstance(diff["policy_violations"], list)
