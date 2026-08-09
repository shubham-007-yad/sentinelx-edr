import uuid
import pytest
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.device import Device, DeviceStatus, OSType
from app.models.usb_event import USBEvent, USBEventType
from app.models.usb_scan_result import USBScanResult
from app.models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.services.response_service import (
    validate_response_request,
    create_response_action,
    dispatch_command_to_agent,
    update_response_action_status,
    execute_response,
    get_response_action_by_id,
    get_response_actions,
    InvalidDeviceError,
    PermissionDeniedError
)


def setup_test_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    return db


def test_validate_response_request_success():
    db = setup_test_db()
    try:
        device = Device(
            hostname="engine-test-host",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()

        # Admin user validation
        validated_dev = validate_response_request(
            db, device.id, initiated_by="admin@sentinelx.io", user_role="ADMIN"
        )
        assert validated_dev.id == device.id

        # Automatic policy validation
        validated_dev_auto = validate_response_request(
            db, device.id, initiated_by="AUTOMATIC"
        )
        assert validated_dev_auto.id == device.id
    finally:
        db.close()


def test_validate_response_request_invalid_device():
    db = setup_test_db()
    try:
        invalid_id = uuid.uuid4()
        with pytest.raises(InvalidDeviceError) as exc_info:
            validate_response_request(db, invalid_id)
        assert "not found" in str(exc_info.value)
    finally:
        db.close()


def test_validate_response_request_permission_denied():
    db = setup_test_db()
    try:
        device = Device(
            hostname="perm-test-host",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()

        with pytest.raises(PermissionDeniedError) as exc_info:
            validate_response_request(
                db, device.id, initiated_by="user@sentinelx.io", user_role="USER"
            )
        assert "Only administrators" in str(exc_info.value)
    finally:
        db.close()


def test_execute_response_and_tracking():
    db = setup_test_db()
    try:
        device = Device(
            hostname="exec-test-host",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()

        # Execute quarantine action
        action = execute_response(
            db=db,
            device_id=device.id,
            action_type=ResponseActionType.QUARANTINE,
            initiated_by="AUTOMATIC"
        )

        assert action.id is not None
        assert action.device_id == device.id
        assert action.action_type == ResponseActionType.QUARANTINE
        assert action.status == ResponseActionStatus.SUCCESS
        assert "dispatched to agent" in action.result

        # Query actions list
        actions = get_response_actions(db, device_id=device.id)
        assert len(actions) == 1
        assert actions[0].id == action.id

        fetched_action = get_response_action_by_id(db, action.id)
        assert fetched_action is not None
        assert fetched_action.id == action.id
    finally:
        db.close()


def test_isolate_device_response_updates_device_status():
    db = setup_test_db()
    try:
        device = Device(
            hostname="isolate-target-host",
            os_type=OSType.LINUX,
            status=DeviceStatus.ONLINE,
            is_active=True
        )
        db.add(device)
        db.commit()

        # Execute isolation action
        action = execute_response(
            db=db,
            device_id=device.id,
            action_type=ResponseActionType.ISOLATE,
            initiated_by="admin@sentinelx.io",
            user_role="ADMIN"
        )

        assert action.status == ResponseActionStatus.SUCCESS

        # Check updated device status
        db.refresh(device)
        assert device.status == DeviceStatus.ISOLATED
    finally:
        db.close()
