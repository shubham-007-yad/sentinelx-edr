import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.main import app
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import SecurityPolicyCreate
from app.services.policy_service import PolicyService
from agent.policy_sync import PolicySyncManager
from agent.background_scanner import USBScanPipelineWorker
from agent.collectors.live_process_monitor import ProcessMonitor
from agent.collectors.network_collector import NetworkMonitor
from agent.integrity_engine import AgentIntegrityEngine


client = TestClient(app)


def _reset_all_policies(db: Session):
    db.query(SecurityPolicy).delete()
    db.commit()


def test_unified_policy_distribution_api():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_all_policies(db)

        # 1. GET initial unified policy
        response = client.get("/api/v1/policies/latest")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "usb" in data
        assert "process" in data
        assert "network" in data
        assert "fim" in data
        assert data["usb"]["max_file_size_mb"] == 50
        assert data["process"]["cpu_threshold_percent"] == 80.0

        # 2. Update USB Policy & Verify version increment
        PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Custom USB Rule",
                category=PolicyCategory.USB,
                version=5,
                enabled=True,
                priority=100,
                configuration={"max_file_size_mb": 10},
                created_by="SecAdmin"
            )
        )

        sync_resp = client.get("/api/v1/policies/sync")
        assert sync_resp.status_code == 200
        sync_data = sync_resp.json()
        assert sync_data["usb"]["max_file_size_mb"] == 10
        assert sync_data["version"] >= 5

    finally:
        db.close()


def test_agent_policy_sync_manager_end_to_end(httpx_mock=None):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _reset_all_policies(db)

        # Instantiate agent modules
        worker = USBScanPipelineWorker(api_client=None)
        proc_mon = ProcessMonitor()
        net_mon = NetworkMonitor()
        fim_engine = AgentIntegrityEngine()

        class MockClient:
            def __init__(self, test_client):
                self.test_client = test_client

            def get(self, url, params=None, timeout=None):
                path = url.replace("http://localhost:8000", "")
                res = self.test_client.get(path, params=params)
                class MockResponse:
                    def __init__(self, r):
                        self.status_code = r.status_code
                        self._data = r.json()
                    def json(self):
                        return self._data
                return MockResponse(res)

        # Create sync manager with mock requests
        sync_mgr = PolicySyncManager(backend_url="http://localhost:8000", poll_interval=1.0)

        # Monkeypatch requests in sync_mgr
        import requests
        mock_http = MockClient(client)
        sync_mgr.fetch_latest_policy = lambda: mock_http.get("http://localhost:8000/api/v1/policies/latest").json()

        # Register callbacks
        received_updates = []
        def handle_policy_update(policy):
            received_updates.append(policy)
            if "usb" in policy:
                worker.update_policy(policy["usb"])
            if "process" in policy:
                proc_mon.update_policy(policy["process"])
            if "network" in policy:
                net_mon.update_policy(policy["network"])
            if "fim" in policy:
                fim_engine.update_policy(policy["fim"])

        sync_mgr.register_callback(handle_policy_update)

        # Execute initial sync
        updated = sync_mgr.sync_once()
        assert updated is True
        assert len(received_updates) == 1
        assert worker.policy["max_file_size_mb"] == 50

        # Update policy in backend
        PolicyService.create_policy(
            db=db,
            payload=SecurityPolicyCreate(
                policy_name="Dynamic Process Blocklist",
                category=PolicyCategory.PROCESS,
                version=10,
                enabled=True,
                priority=200,
                configuration={"blocklisted_processes": ["bad_tool.exe"], "auto_kill_blocklisted": True},
                created_by="Admin"
            )
        )

        # Execute second sync
        updated_2 = sync_mgr.sync_once()
        assert updated_2 is True
        assert len(received_updates) == 2
        assert "bad_tool.exe" in proc_mon.policy["blocklisted_processes"]
        assert proc_mon.policy["auto_kill_blocklisted"] is True

    finally:
        db.close()
