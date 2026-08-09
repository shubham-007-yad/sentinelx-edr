import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.main import app
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import FIMPolicyConfigSchema
from app.services.policy_service import PolicyService, DEFAULT_FIM_CONFIG
from agent.integrity_engine import AgentIntegrityEngine


client = TestClient(app)


def _reset_policies(db: Session):
    db.query(SecurityPolicy).filter(SecurityPolicy.category.in_([PolicyCategory.FIM, PolicyCategory.RANSOMWARE])).delete()
    db.commit()


def test_fim_policy_service_defaults():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
        config = PolicyService.get_active_fim_policy(db)
        assert "Desktop" in config["protected_folders"]
        assert "node_modules" in config["excluded_folders"]
        assert config["ransomware_entropy_threshold"] == 7.2
        assert config["ignore_temporary_files"] is True
    finally:
        db.close()


def test_fim_policy_api_endpoints():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
    finally:
        db.close()

    # 1. GET initial FIM policy
    response = client.get("/api/v1/fim/policy")
    assert response.status_code == 200
    data = response.json()
    assert "Desktop" in data["protected_folders"]
    assert data["ransomware_entropy_threshold"] == 7.2

    # 2. PUT updated FIM policy
    updated_payload = {
        "protected_folders": ["Desktop", "CustomVault"],
        "excluded_folders": [".git", "cache_dir"],
        "hash_algorithm": "SHA-256",
        "ransomware_modification_threshold": 10,
        "ransomware_entropy_threshold": 6.8,
        "ignore_temporary_files": True,
        "auto_quarantine_ransomware": True
    }

    put_resp = client.put("/api/v1/fim/policy", json=updated_payload)
    assert put_resp.status_code == 200
    res_data = put_resp.json()
    assert "CustomVault" in res_data["protected_folders"]
    assert res_data["ransomware_modification_threshold"] == 10
    assert res_data["ransomware_entropy_threshold"] == 6.8

    # 3. GET verify persistence
    get_resp2 = client.get("/api/v1/fim/policy")
    assert get_resp2.status_code == 200
    assert get_resp2.json()["ransomware_modification_threshold"] == 10


def test_agent_integrity_engine_policy_filtering():
    custom_policy = {
        "excluded_folders": ["node_modules", "vendor"],
        "ignore_temporary_files": True
    }

    engine_inst = AgentIntegrityEngine(policy=custom_policy)

    # Test excluded folder
    res_ex = engine_inst.process_file_event({
        "event_type": "MODIFIED",
        "file_path": "/home/user/project/node_modules/package/index.js"
    })
    assert res_ex["status"] == "IGNORED_BY_POLICY"

    # Test temp file
    res_tmp = engine_inst.process_file_event({
        "event_type": "CREATED",
        "file_path": "/home/user/Documents/draft.tmp"
    })
    assert res_tmp["status"] == "IGNORED_BY_POLICY"

    # Test valid monitored file
    res_valid = engine_inst.process_file_event({
        "event_type": "CREATED",
        "file_path": "/home/user/Documents/important.docx",
        "sha256": "abcdef123456"
    })
    assert res_valid["status"] == "NEW_FILE"
