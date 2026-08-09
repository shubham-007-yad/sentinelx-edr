import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.models.user import User, UserRole
from app.models.device import Device, DeviceStatus, OSType
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.threat import Threat, ThreatSeverity, ThreatType
from app.auth.jwt import create_access_token


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def admin_headers(setup_db: Session):
    db = setup_db
    user = db.query(User).filter(User.username == "admin_phase3_test").first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            username="admin_phase3_test",
            email="admin_p3@sentinelx.io",
            password_hash="pass_hash",
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token(subject=user.username, role="ADMIN")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def analyst_headers(setup_db: Session):
    db = setup_db
    user = db.query(User).filter(User.username == "analyst_phase3_test").first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            username="analyst_phase3_test",
            email="analyst_p3@sentinelx.io",
            password_hash="pass_hash",
            role=UserRole.ANALYST,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token(subject=user.username, role="ANALYST")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def viewer_headers(setup_db: Session):
    db = setup_db
    user = db.query(User).filter(User.username == "viewer_phase3_test").first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            username="viewer_phase3_test",
            email="viewer_p3@sentinelx.io",
            password_hash="pass_hash",
            role=UserRole.VIEWER,
            is_active=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token(subject=user.username, role="VIEWER")
    return {"Authorization": f"Bearer {token}"}


def test_phase3_admin_role_capabilities(setup_db: Session, admin_headers: dict):
    """Verifies ADMIN role access to Users, Policies, Fleet, Config, Security Actions, Reports."""
    db = setup_db
    client = TestClient(app)

    # 1. Users Management
    new_user_res = client.post("/api/v1/users", json={
        "username": "created_by_admin",
        "email": "created_by_admin@sentinelx.io",
        "password": "Password123!",
        "role": "ANALYST"
    }, headers=admin_headers)
    assert new_user_res.status_code in [201, 400]

    # 2. Policies Management
    pol_res = client.post("/api/v1/policies", json={
        "policy_name": "Admin Test USB Policy",
        "category": "USB",
        "configuration": {"block_unauthorized": True}
    }, headers=admin_headers)
    assert pol_res.status_code == 201

    # 3. USB Configuration
    usb_pol_res = client.put("/api/v1/usb/policy", json={
        "block_unauthorized_usb": True,
        "allow_storage_devices": False,
        "allowed_vendor_ids": ["0781"]
    }, headers=admin_headers)
    assert usb_pol_res.status_code == 200

    # 4. Fleet Commands
    target_dev = uuid.uuid4()
    device = Device(
        id=target_dev,
        hostname="HOST-ADMIN-TEST",
        ip_address="192.168.1.55",
        os_type=OSType.WINDOWS,
        status=DeviceStatus.ONLINE
    )
    db.add(device)
    db.commit()

    cmd_res = client.post("/api/v1/fleet/commands", json={
        "device_id": str(target_dev),
        "command_type": "COLLECT_DIAGNOSTICS"
    }, headers=admin_headers)
    assert cmd_res.status_code == 201

    # 5. Security Actions
    resp_res = client.post("/api/v1/responses/trigger", json={
        "device_id": str(target_dev),
        "action_type": "BLOCK_IP",
        "parameters": {"remote_ip": "1.2.3.4"}
    }, headers=admin_headers)
    assert resp_res.status_code == 201

    # 6. Reports & Dashboard Analytics
    analytics_res = client.get("/api/v1/analytics/dashboard", headers=admin_headers)
    assert analytics_res.status_code == 200


def test_phase3_analyst_role_capabilities_and_restrictions(setup_db: Session, analyst_headers: dict):
    """Verifies ANALYST role access to Threats, Alerts, Investigations, Telemetry, Response, Reports, and Admin blocks."""
    client = TestClient(app)

    # 1. Threats
    assert client.get("/api/v1/threats", headers=analyst_headers).status_code == 200

    # 2. Alerts
    assert client.get("/api/v1/alerts", headers=analyst_headers).status_code == 200

    # 3. Telemetry
    assert client.get("/api/v1/telemetry/logs", headers=analyst_headers).status_code == 200

    # 4. Case Investigation Creation
    case_res = client.post("/api/v1/investigation/cases", json={
        "title": "Analyst Investigation Case",
        "description": "Triage investigation by analyst",
        "severity": "HIGH"
    }, headers=analyst_headers)
    assert case_res.status_code == 201

    # 5. Reports
    assert client.get("/api/v1/analytics/dashboard", headers=analyst_headers).status_code == 200

    # 6. RESTRICTION CHECKS (Analyst cannot access Admin endpoints)
    assert client.post("/api/v1/users", json={
        "username": "unauthorized_analyst_user",
        "email": "unauth_a@sentinelx.io",
        "password": "Password123!",
        "role": "VIEWER"
    }, headers=analyst_headers).status_code == 403

    assert client.post("/api/v1/policies", json={
        "policy_name": "Forbidden Policy",
        "category": "NETWORK"
    }, headers=analyst_headers).status_code == 403

    assert client.post("/api/v1/fleet/commands", json={
        "device_id": str(uuid.uuid4()),
        "command_type": "RESTART_AGENT"
    }, headers=analyst_headers).status_code == 403


def test_phase3_viewer_role_read_only_and_bypass_prevention(setup_db: Session, viewer_headers: dict):
    """Verifies VIEWER role read-only access to Dashboards & Reports, and strict API bypass prevention."""
    client = TestClient(app)

    # 1. Dashboards & Analytics
    assert client.get("/api/v1/analytics/dashboard", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/analytics/top-metrics", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/analytics/endpoint-risk", headers=viewer_headers).status_code == 200

    # 2. Reports
    assert client.get("/api/v1/scheduled-reports", headers=viewer_headers).status_code == 200

    # 3. Read-Only Data Streams
    assert client.get("/api/v1/devices", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/alerts", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/threats", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/investigation/cases", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/policies/history", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/telemetry/logs", headers=viewer_headers).status_code == 200

    # 4. STRICT BYPASS PREVENTION TESTS (Viewer attempting privileged API mutations)
    # Bypass 1: Users API
    assert client.post("/api/v1/users", json={
        "username": "bypass_user",
        "email": "bypass@sentinelx.io",
        "password": "Password123!",
        "role": "ADMIN"
    }, headers=viewer_headers).status_code == 403

    # Bypass 2: Policies API
    assert client.post("/api/v1/policies", json={
        "policy_name": "Viewer Bypass Policy",
        "category": "USB"
    }, headers=viewer_headers).status_code == 403

    # Bypass 3: Fleet Commands API
    assert client.post("/api/v1/fleet/commands", json={
        "device_id": str(uuid.uuid4()),
        "command_type": "SHUTDOWN_AGENT"
    }, headers=viewer_headers).status_code == 403

    # Bypass 4: Response Engine API
    assert client.post("/api/v1/responses/trigger", json={
        "device_id": str(uuid.uuid4()),
        "action_type": "TERMINATE_PROCESS"
    }, headers=viewer_headers).status_code == 403

    # Bypass 5: Case Creation API
    assert client.post("/api/v1/investigation/cases", json={
        "title": "Viewer Bypass Case",
        "severity": "CRITICAL"
    }, headers=viewer_headers).status_code == 403

    # Bypass 6: USB Policy Update API
    assert client.put("/api/v1/usb/policy", json={
        "block_unauthorized_usb": False
    }, headers=viewer_headers).status_code == 403
