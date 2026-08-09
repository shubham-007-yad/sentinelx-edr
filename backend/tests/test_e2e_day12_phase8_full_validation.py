import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.db.init_db import init_db
from app.models.device import Device, DeviceStatus, OSType
from app.models.event_log import SecurityEvent
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.models.response_audit_log import ResponseAuditLog
from app.services import event_log_service, response_service


@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        init_db(session)
    except Exception:
        pass
    yield session
    session.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def phase8_event_device(db_session):
    device = Device(
        id=uuid.uuid4(),
        hostname="day12-phase8-validator",
        ip_address="192.168.1.150",
        os_type=OSType.WINDOWS,
        status=DeviceStatus.ONLINE,
        is_active=True
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)
    return device


def test_phase8_complete_event_log_validation(db_session, client, phase8_event_device):
    dev_id = phase8_event_device.id
    dev_id_str = str(dev_id)

    # -------------------------------------------------------------------------
    # Validation 1: Successful Login
    # -------------------------------------------------------------------------
    success_evt = [{
        "id": str(uuid.uuid4()),
        "device_id": dev_id_str,
        "event_source": "Security",
        "event_id": "4624",
        "event_type": "AUTHENTICATION_SUCCESS",
        "level": "Information",
        "username": "legit_user",
        "computer": phase8_event_device.hostname,
        "logon_type": "2-Interactive",
        "ip_address": "127.0.0.1",
        "status": "SUCCESS",
        "description": "User legit_user logged in interactively.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }]
    res1 = event_log_service.ingest_security_events(db_session, dev_id, success_evt)
    assert res1["status"] == "SUCCESS"
    assert res1["ingested"] == 1

    stored_success = db_session.query(SecurityEvent).filter(
        SecurityEvent.device_id == dev_id,
        SecurityEvent.event_type == "AUTHENTICATION_SUCCESS"
    ).first()
    assert stored_success is not None
    assert stored_success.username == "legit_user"

    # -------------------------------------------------------------------------
    # Validation 2: Failed Login
    # -------------------------------------------------------------------------
    failed_evt = [{
        "id": str(uuid.uuid4()),
        "device_id": dev_id_str,
        "event_source": "Security",
        "event_id": "4625",
        "event_type": "AUTHENTICATION_FAILURE",
        "level": "Warning",
        "username": "failed_target",
        "computer": phase8_event_device.hostname,
        "logon_type": "10-RemoteDesktop",
        "ip_address": "203.0.113.88",
        "status": "FAILED",
        "description": "Failed logon attempt for failed_target.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }]
    res2 = event_log_service.ingest_security_events(db_session, dev_id, failed_evt)
    assert res2["status"] == "SUCCESS"

    stored_failed = db_session.query(SecurityEvent).filter(
        SecurityEvent.device_id == dev_id,
        SecurityEvent.event_type == "AUTHENTICATION_FAILURE"
    ).first()
    assert stored_failed is not None
    assert stored_failed.status == "FAILED"

    # -------------------------------------------------------------------------
    # Validation 3: Brute-Force Detection (5 rapid failures)
    # -------------------------------------------------------------------------
    bf_events = []
    ts_now = datetime.now(timezone.utc).isoformat()
    for i in range(5):
        bf_events.append({
            "id": str(uuid.uuid4()),
            "device_id": dev_id_str,
            "event_source": "Security",
            "event_id": "4625",
            "event_type": "AUTHENTICATION_FAILURE",
            "level": "Warning",
            "username": "brute_force_target",
            "computer": phase8_event_device.hostname,
            "logon_type": "10-RemoteDesktop",
            "ip_address": "198.51.100.99",
            "status": "FAILED",
            "description": f"Failed logon #{i+1} for brute_force_target",
            "timestamp": ts_now
        })
    res3 = event_log_service.ingest_security_events(db_session, dev_id, bf_events)
    assert res3["threats_detected"] >= 1

    bf_threat = db_session.query(Threat).filter(
        Threat.rule_name == "Possible Brute Force"
    ).order_by(Threat.detected_at.desc()).first()
    assert bf_threat is not None
    assert bf_threat.severity.value == "CRITICAL"

    # -------------------------------------------------------------------------
    # Validation 4: Privilege Escalation
    # -------------------------------------------------------------------------
    priv_evt = [{
        "id": str(uuid.uuid4()),
        "device_id": dev_id_str,
        "event_source": "Security",
        "event_id": "4732",
        "event_type": "PRIVILEGE_ESCALATION",
        "level": "Warning",
        "username": "escalated_user",
        "computer": phase8_event_device.hostname,
        "status": "SUCCESS",
        "description": "User escalated_user added to Administrators group",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }]
    res4 = event_log_service.ingest_security_events(db_session, dev_id, priv_evt)
    assert res4["threats_detected"] >= 1

    priv_threat = db_session.query(Threat).filter(
        Threat.rule_name == "New Administrator Account"
    ).order_by(Threat.detected_at.desc()).first()
    assert priv_threat is not None

    # -------------------------------------------------------------------------
    # Validation 5: New Service Creation
    # -------------------------------------------------------------------------
    svc_evt = [{
        "id": str(uuid.uuid4()),
        "device_id": dev_id_str,
        "event_source": "System",
        "event_id": "4697",
        "event_type": "PERSISTENCE",
        "level": "Warning",
        "username": "SYSTEM",
        "computer": phase8_event_device.hostname,
        "status": "SUCCESS",
        "description": "A service was installed in the system: MalwareService",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }]
    res5 = event_log_service.ingest_security_events(db_session, dev_id, svc_evt)
    assert res5["threats_detected"] >= 1

    svc_threat = db_session.query(Threat).filter(
        Threat.rule_name == "New Windows Service Creation"
    ).order_by(Threat.detected_at.desc()).first()
    assert svc_threat is not None

    # -------------------------------------------------------------------------
    # Validation 6: Scheduled Task Creation
    # -------------------------------------------------------------------------
    task_evt = [{
        "id": str(uuid.uuid4()),
        "device_id": dev_id_str,
        "event_source": "Security",
        "event_id": "4702",
        "event_type": "PERSISTENCE",
        "level": "Warning",
        "username": "SYSTEM",
        "computer": phase8_event_device.hostname,
        "status": "SUCCESS",
        "description": "New Scheduled Task created: TaskName=\\UpdaterSvcTask",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }]
    res6 = event_log_service.ingest_security_events(db_session, dev_id, task_evt)
    assert res6["threats_detected"] >= 1

    task_threat = db_session.query(Threat).filter(
        Threat.rule_name == "Scheduled Task Persistence Creation"
    ).order_by(Threat.detected_at.desc()).first()
    assert task_threat is not None

    # -------------------------------------------------------------------------
    # Validation 7: Dashboard Updates (API summary & attack chain endpoints)
    # -------------------------------------------------------------------------
    summary = event_log_service.get_authentication_summary(db_session, dev_id)
    assert summary["total_events"] >= 10
    assert summary["logins"] >= 1
    assert summary["failed_logons"] >= 6
    assert summary["privilege_changes"] >= 1
    assert summary["persistence_events"] >= 2

    chain = event_log_service.get_attack_chain_timeline(db_session, dev_id)
    assert len(chain) >= 5
    assert any(step["event_title"] in ["Failed Login", "Administrator Login", "New Scheduled Task"] for step in chain)

    # -------------------------------------------------------------------------
    # Validation 8: Phase 6 Response Actions & Mandatory Audit Logging
    # -------------------------------------------------------------------------
    actions_to_validate = [
        (ResponseActionType.DISABLE_USER, {"target_user": "brute_force_target"}),
        (ResponseActionType.FORCE_LOGOUT, {"target_user": "brute_force_target"}),
        (ResponseActionType.INVESTIGATE, {"event_id": "4625"}),
        (ResponseActionType.IGNORE, {"event_id": "4624"}),
        (ResponseActionType.ALLOWLIST_EVENT, {"target_user": "legit_user"})
    ]

    for act_type, params in actions_to_validate:
        action_obj = response_service.execute_response(
            db=db_session,
            device_id=dev_id,
            action_type=act_type,
            initiated_by="PHASE8_VALIDATOR",
            user_role="ADMIN",
            parameters=params
        )
        assert action_obj.status == ResponseActionStatus.SUCCESS

        audit_logs = db_session.query(ResponseAuditLog).filter(
            ResponseAuditLog.action_id == action_obj.id
        ).all()
        assert len(audit_logs) >= 3
        stages = [log.stage for log in audit_logs]
        assert "INITIATED" in stages
        assert "SUCCESS" in stages
