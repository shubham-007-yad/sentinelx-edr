import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.main import app
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import (
    SecurityPolicyCreate, SecurityPolicyUpdate,
    USBPolicyConfigSchema, ProcessPolicyConfigSchema,
    NetworkPolicyConfigSchema, FIMPolicyConfigSchema
)
from app.services.policy_service import PolicyService
from agent.policy_sync import PolicySyncManager
from agent.background_scanner import USBScanPipelineWorker
from agent.collectors.live_process_monitor import ProcessMonitor
from agent.collectors.network_collector import NetworkMonitor
from agent.integrity_engine import AgentIntegrityEngine


client = TestClient(app)


def _reset_db(db: Session):
    db.query(SecurityPolicy).delete()
    db.commit()


def test_phase8_policy_creation_and_editing():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_db(db)

        # 1. Policy Creation across categories
        usb_pol = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Strict USB Restriction Policy",
                category=PolicyCategory.USB,
                version=1,
                enabled=True,
                priority=100,
                configuration={"max_file_size_mb": 15, "read_only_mode": True},
                created_by="AdminSec"
            )
        )
        assert usb_pol.id is not None
        assert usb_pol.configuration["max_file_size_mb"] == 15
        assert usb_pol.configuration["read_only_mode"] is True

        proc_pol = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Process Isolation Policy",
                category=PolicyCategory.PROCESS,
                version=1,
                enabled=True,
                priority=100,
                configuration={"blocklisted_processes": ["nc.exe", "evil.exe"], "auto_kill_blocklisted": True},
                created_by="AdminSec"
            )
        )
        assert proc_pol.configuration["auto_kill_blocklisted"] is True

        # 2. Policy Editing & Version Update
        updated_usb = PolicyService.update_policy(
            db=db,
            policy_id=str(usb_pol.id),
            payload=SecurityPolicyUpdate(
                configuration={"max_file_size_mb": 25, "block_unauthorized_usbs": True}
            )
        )
        assert updated_usb.version == 2
        assert updated_usb.configuration["max_file_size_mb"] == 25
        assert updated_usb.configuration["block_unauthorized_usbs"] is True

    finally:
        db.close()


def test_phase8_agent_synchronization_and_version_updates():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_db(db)

        # Setup initial policies
        usb_pol = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="USB Scan Policy",
                category=PolicyCategory.USB,
                version=1,
                enabled=True,
                priority=50,
                configuration={"max_file_size_mb": 100},
                created_by="Admin"
            )
        )

        net_pol = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Network Defense Policy",
                category=PolicyCategory.NETWORK,
                version=1,
                enabled=True,
                priority=50,
                configuration={"blocked_ports": [6667, 31337], "auto_block_c2_connections": True},
                created_by="Admin"
            )
        )

        # Agent collectors setup
        worker = USBScanPipelineWorker(api_client=None)
        proc_mon = ProcessMonitor()
        net_mon = NetworkMonitor()
        fim_engine = AgentIntegrityEngine()

        class MockSyncClient:
            def __init__(self, test_client):
                self.tc = test_client

            def get(self, url, params=None):
                res = self.tc.get("/api/v1/policies/latest", params=params)
                class Resp:
                    def __init__(self, r):
                        self.status_code = r.status_code
                        self._data = r.json()
                    def json(self):
                        return self._data
                return Resp(res)

        mock_http = MockSyncClient(client)
        sync_mgr = PolicySyncManager(backend_url="http://localhost:8000", poll_interval=1.0)
        sync_mgr.fetch_latest_policy = lambda: mock_http.get("/api/v1/policies/latest").json()

        def apply_all(payload):
            if "usb" in payload:
                worker.update_policy(payload["usb"])
            if "process" in payload:
                proc_mon.update_policy(payload["process"])
            if "network" in payload:
                net_mon.update_policy(payload["network"])
            if "fim" in payload:
                fim_engine.update_policy(payload["fim"])

        sync_mgr.register_callback(apply_all)

        # Initial Agent Sync
        synced = sync_mgr.sync_once()
        assert synced is True
        assert worker.policy["max_file_size_mb"] == 100
        assert 6667 in net_mon.policy["blocked_ports"]

        # Edit Policy & Verify Sync Version Increment
        PolicyService.update_policy(
            db=db,
            policy_id=str(net_pol.id),
            payload=SecurityPolicyUpdate(
                configuration={"blocked_ports": [6667, 31337, 9999]}
            )
        )

        synced_2 = sync_mgr.sync_once()
        assert synced_2 is True
        assert 9999 in net_mon.policy["blocked_ports"]

    finally:
        db.close()


def test_phase8_policy_rollback_and_cloning():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_db(db)

        # Create Version 1
        pol_v1 = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Baseline FIM Policy",
                category=PolicyCategory.FIM,
                version=1,
                enabled=True,
                priority=10,
                configuration={"ransomware_modification_threshold": 30},
                created_by="Admin"
            )
        )

        # Create Version 2 (Higher Priority)
        pol_v2 = PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Aggressive FIM Policy",
                category=PolicyCategory.FIM,
                version=2,
                enabled=True,
                priority=50,
                configuration={"ransomware_modification_threshold": 5},
                created_by="Admin"
            )
        )

        active_before = PolicyService.get_active_fim_policy(db)
        assert active_before["ransomware_modification_threshold"] == 5

        # Rollback to Version 1
        rolled = PolicyService.rollback_policy(db=db, policy_id=str(pol_v1.id))
        assert rolled.enabled is True
        assert rolled.priority == 999

        active_after = PolicyService.get_active_fim_policy(db)
        assert active_after["ransomware_modification_threshold"] == 30

        # Clone Policy
        cloned = PolicyService.clone_policy(db=db, policy_id=str(pol_v1.id))
        assert "Copy" in cloned.policy_name
        assert cloned.configuration["ransomware_modification_threshold"] == 30

    finally:
        db.close()


def test_phase8_dashboard_api_endpoints():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_db(db)
    finally:
        db.close()

    # GET /api/v1/policies/history
    resp_hist = client.get("/api/v1/policies/history")
    assert resp_hist.status_code == 200
    assert isinstance(resp_hist.json(), list)

    # GET /api/v1/policies/latest
    resp_latest = client.get("/api/v1/policies/latest")
    assert resp_latest.status_code == 200
    data = resp_latest.json()
    assert "version" in data
    assert "usb" in data
    assert "process" in data
    assert "network" in data
    assert "fim" in data
