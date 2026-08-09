import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.main import app
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import USBPolicyConfigSchema, SecurityPolicyCreate
import uuid
from app.models.user import User, UserRole
from app.auth.jwt import create_access_token
from app.services.policy_service import PolicyService, DEFAULT_USB_CONFIG
from agent.background_scanner import USBScanPipelineWorker


client = TestClient(app)


def _reset_policies(db: Session):
    db.query(SecurityPolicy).delete()
    db.commit()


def test_usb_policy_service_defaults():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
        # Default policy returned when database is empty
        config = PolicyService.get_active_usb_policy(db)
        assert config["enable_usb_monitoring"] is True
        assert config["enable_auto_scanning"] is True
        assert config["max_file_size_mb"] == 50
        assert ".tmp" in config["ignored_extensions"]
    finally:
        db.close()


def test_usb_policy_api_endpoints():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_policies(db)
        user = db.query(User).filter(User.username == "usb_pol_admin").first()
        if not user:
            user = User(
                id=uuid.uuid4(),
                username="usb_pol_admin",
                email="usb_pol@sentinelx.io",
                password_hash="pass_hash",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(user)
            db.commit()
    finally:
        db.close()

    token = create_access_token(subject="usb_pol_admin", role="ADMIN")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. GET initial policy

    response = client.get("/api/v1/usb/policy")
    assert response.status_code == 200
    data = response.json()
    assert data["enable_usb_monitoring"] is True
    assert data["max_file_size_mb"] == 50

    # 2. PUT updated policy
    updated_payload = {
        "enable_usb_monitoring": True,
        "enable_auto_scanning": True,
        "scan_removable_only": True,
        "max_file_size_mb": 10,
        "ignored_extensions": [".tmp", ".log", ".iso"],
        "enable_sha256_hashing": False,
        "block_unauthorized_usbs": True,
        "auto_quarantine_suspicious": True,
        "allowed_vendor_ids": ["0781", "0951"],
        "read_only_mode": True
    }

    put_resp = client.put("/api/v1/usb/policy", json=updated_payload, headers=headers)
    assert put_resp.status_code == 200
    res_data = put_resp.json()
    assert res_data["max_file_size_mb"] == 10
    assert res_data["enable_sha256_hashing"] is False
    assert res_data["auto_quarantine_suspicious"] is True
    assert res_data["allowed_vendor_ids"] == ["0781", "0951"]

    # 3. GET verify persistence
    get_resp2 = client.get("/api/v1/usb/policy")
    assert get_resp2.status_code == 200
    assert get_resp2.json()["max_file_size_mb"] == 10


def test_agent_worker_policy_enforcement():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test files
        tmp_file = os.path.join(tmp_dir, "test_log.tmp")
        with open(tmp_file, "w") as f:
            f.write("temporary log file")

        large_file = os.path.join(tmp_dir, "large_data.dat")
        with open(large_file, "wb") as f:
            f.write(b"0" * (2 * 1024 * 1024))  # 2 MB file

        normal_file = os.path.join(tmp_dir, "document.pdf")
        with open(normal_file, "w") as f:
            f.write("valid document content")

        malicious_script = os.path.join(tmp_dir, "payload.vbs")
        with open(malicious_script, "w") as f:
            f.write("WScript.Echo 'test'")

        # Instantiate worker with strict custom policy:
        # Max file size: 1MB, Ignored ext: [.tmp], Hashing disabled, Auto Quarantine enabled
        custom_policy = {
            "enable_usb_monitoring": True,
            "enable_auto_scanning": True,
            "scan_removable_only": False,
            "max_file_size_mb": 1,
            "ignored_extensions": [".tmp"],
            "enable_sha256_hashing": False,
            "auto_quarantine_suspicious": True
        }

        class MockAPIClient:
            def __init__(self):
                self.sent_batches = []

            def send_usb_scans(self, scans):
                self.sent_batches.extend(scans)
                return {"status": "ok"}

        mock_api = MockAPIClient()
        worker = USBScanPipelineWorker(api_client=mock_api, batch_size=10, policy=custom_policy)

        # Execute scan task on temporary directory
        summary = worker.process_scan_task(usb_event_id="test-event-id", drive_letter=tmp_dir)

        # Assertions
        # 1. Ignored extension (.tmp) & large file (>1MB) should be skipped by policy
        assert summary["skipped_policy_count"] == 2
        
        # 2. Hashing was set to false
        for uploaded in mock_api.sent_batches:
            assert uploaded["sha256"] == ""

        # 3. Auto quarantine moved payload.vbs
        assert summary["quarantined_count"] == 1
        assert not os.path.exists(malicious_script)
