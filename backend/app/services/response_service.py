import logging
from typing import Optional, List
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.device import Device, DeviceStatus
from app.models.alert import Alert
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.models.response_audit_log import ResponseAuditLog
from app.core.websocket_manager import websocket_manager

import hmac
import hashlib
from app.core.settings import settings

logger = logging.getLogger(__name__)


def compute_command_signature(action_id: str, action_type: str, timestamp: str, device_id: str, secret: str) -> str:
    """Computes HMAC-SHA256 signature over command parameters."""
    msg = f"{action_id}:{action_type}:{timestamp}:{device_id}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


class ResponseServiceError(Exception):
    """Base exception for Response Engine errors."""
    pass


class InvalidDeviceError(ResponseServiceError):
    """Raised when target endpoint device is invalid or not found."""
    pass


class PermissionDeniedError(ResponseServiceError):
    """Raised when user lacks permission to initiate a response action."""
    pass


class DuplicateActionError(ResponseServiceError):
    """Raised when an identical response action is already PENDING or RUNNING for the target endpoint."""
    pass


def validate_response_request(
    db: Session,
    device_id: UUID,
    initiated_by: str = "AUTOMATIC",
    user_role: Optional[str] = None
) -> Device:
    """
    Validates permissions and device existence prior to executing a response action.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        logger.error(f"[ResponseEngine] Device not found: {device_id}")
        raise InvalidDeviceError(f"Device with ID {device_id} not found.")

    if not device.is_active:
        logger.warning(f"[ResponseEngine] Device is inactive: {device_id}")
        raise InvalidDeviceError(f"Device {device.hostname} ({device_id}) is inactive.")

    # Permission check for admin-initiated actions
    if initiated_by != "AUTOMATIC" and user_role is not None:
        if user_role.upper() not in ["ADMIN", "SUPERADMIN", "ANALYST"]:
            logger.warning(f"[ResponseEngine] Permission denied for user role '{user_role}' on device {device_id}")
            raise PermissionDeniedError("Only administrators and analysts can initiate manual response actions.")

    return device


def add_audit_log(
    db: Session,
    action_id: UUID,
    stage: str,
    actor: str,
    message: str,
    details: Optional[dict] = None
) -> ResponseAuditLog:
    """
    Records a step in the forensic audit trail for a response action.
    """
    log_entry = ResponseAuditLog(
        action_id=action_id,
        stage=stage,
        actor=actor,
        message=message,
        details=details
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    logger.info(f"[ResponseEngine AUDIT TRAIL] Action {action_id} | Stage: {stage} | Actor: {actor} | Msg: {message}")
    return log_entry


def create_response_action(
    db: Session,
    device_id: UUID,
    action_type: ResponseActionType,
    alert_id: Optional[UUID] = None,
    initiated_by: str = "AUTOMATIC",
    result: Optional[str] = None,
    parameters: Optional[dict] = None
) -> ResponseAction:
    """
    Creates and persists a new ResponseAction record in PENDING state with forensic audit logs.
    """
    # Duplicate command check for PENDING or RUNNING actions
    existing = (
        db.query(ResponseAction)
        .filter(
            ResponseAction.device_id == device_id,
            ResponseAction.action_type == action_type,
            ResponseAction.status.in_([ResponseActionStatus.PENDING, ResponseActionStatus.RUNNING])
        )
        .first()
    )
    if existing:
        logger.warning(f"[ResponseEngine] Duplicate active action detected for device {device_id}: Action ID {existing.id}")
        raise DuplicateActionError(f"Action '{action_type.value}' is already {existing.status.value} for device {device_id}.")

    if alert_id:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            logger.warning(f"[ResponseEngine] Alert ID {alert_id} not found when linking response action.")

    action = ResponseAction(
        device_id=device_id,
        alert_id=alert_id,
        action_type=action_type,
        status=ResponseActionStatus.PENDING,
        initiated_by=initiated_by,
        result=result or f"Action {action_type} queued for execution."
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    audit_details = {
        "device_id": str(device_id),
        "action_type": action_type.value,
        "alert_id": str(alert_id) if alert_id else None
    }
    if parameters:
        audit_details.update(parameters)

    # Forensic Audit Log Entry: INITIATED
    add_audit_log(
        db=db,
        action_id=action.id,
        stage="INITIATED",
        actor=initiated_by,
        message=f"{initiated_by} initiated {action_type.value} action on device.",
        details=audit_details
    )

    logger.info(
        f"[ResponseEngine AUDIT] ResponseAction created: id={action.id}, "
        f"device_id={device_id}, action_type={action_type}, initiated_by={initiated_by}"
    )
    return action


def dispatch_command_to_agent(action: ResponseAction, device: Device, db: Optional[Session] = None) -> bool:
    """
    Dispatches a response command to the endpoint agent via WebSocket / real-time channel.
    Returns True if command dispatch payload was successfully broadcasted/emitted.
    """
    logger.info(
        f"[ResponseEngine] Dispatching command '{action.action_type}' (Action ID: {action.id}) "
        f"to target endpoint {device.hostname} ({device.ip_address})"
    )

    ts_str = datetime.now(timezone.utc).isoformat()
    action_id_str = str(action.id)
    device_id_str = str(device.id)
    action_type_str = action.action_type.value
    sig = compute_command_signature(action_id_str, action_type_str, ts_str, device_id_str, settings.JWT_SECRET)

    payload = {
        "event": "RESPONSE_COMMAND",
        "data": {
            "action_id": action_id_str,
            "device_id": device_id_str,
            "alert_id": str(action.alert_id) if action.alert_id else None,
            "action_type": action_type_str,
            "status": action.status.value,
            "timestamp": ts_str,
            "signature": sig
        }
    }

    try:
        websocket_manager.broadcast_sync(payload)
        logger.info(f"[ResponseEngine] Command successfully dispatched for Action ID {action.id}")

        if db:
            add_audit_log(
                db=db,
                action_id=action.id,
                stage="ACKNOWLEDGED",
                actor=f"Agent ({device.hostname})",
                message=f"Agent on {device.hostname} acknowledged command '{action.action_type}'.",
                details={"hostname": device.hostname, "ip_address": device.ip_address}
            )

        return True
    except Exception as e:
        logger.error(f"[ResponseEngine] Failed to dispatch command for Action ID {action.id}: {e}")
        if db:
            add_audit_log(
                db=db,
                action_id=action.id,
                stage="FAILED",
                actor="System",
                message=f"Failed to dispatch command to {device.hostname}: {e}"
            )
        return False


def update_response_action_status(
    db: Session,
    action_id: UUID,
    status: ResponseActionStatus,
    result: Optional[str] = None
) -> Optional[ResponseAction]:
    """
    Updates the execution status and details of an existing ResponseAction.
    If action_type is ISOLATE and status is SUCCESS, updates target device status to ISOLATED.
    """
    action = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not action:
        logger.error(f"[ResponseEngine] ResponseAction not found: {action_id}")
        return None

    action.status = status
    if result:
        action.result = result

    if status in [ResponseActionStatus.SUCCESS, ResponseActionStatus.FAILED, ResponseActionStatus.CANCELLED]:
        action.completed_at = datetime.now(timezone.utc)

    # Perform device state updates if response action succeeded
    if status == ResponseActionStatus.SUCCESS:
        device = db.query(Device).filter(Device.id == action.device_id).first()
        if device and action.action_type == ResponseActionType.ISOLATE:
            device.status = DeviceStatus.ISOLATED
            db.add(device)
            logger.info(f"[ResponseEngine AUDIT] Device {device.hostname} ({device.id}) marked as ISOLATED.")

    db.add(action)
    db.commit()
    db.refresh(action)

    # Forensic Audit Log Entry for Execution Outcome
    stage_name = status.value
    msg = result or f"Action status set to {status.value}."
    add_audit_log(
        db=db,
        action_id=action.id,
        stage=stage_name,
        actor=action.initiated_by if status == ResponseActionStatus.CANCELLED else "Agent Engine",
        message=msg,
        details={"result": result, "status": status.value}
    )

    logger.info(
        f"[ResponseEngine AUDIT] ResponseAction updated: id={action.id}, "
        f"status={status}, completed_at={action.completed_at}"
    )

    # Broadcast status update via WebSocket
    broadcast_payload = {
        "event": "RESPONSE_STATUS_UPDATE",
        "data": {
            "action_id": str(action.id),
            "device_id": str(action.device_id),
            "action_type": action.action_type.value,
            "status": action.status.value,
            "result": action.result,
            "completed_at": action.completed_at.isoformat() if action.completed_at else None
        }
    }
    try:
        websocket_manager.broadcast_sync(broadcast_payload)
    except Exception as e:
        logger.warning(f"[ResponseEngine] Failed to broadcast status update: {e}")

    return action


def execute_response(
    db: Session,
    device_id: UUID,
    action_type: ResponseActionType,
    alert_id: Optional[UUID] = None,
    initiated_by: str = "AUTOMATIC",
    user_role: Optional[str] = None,
    parameters: Optional[dict] = None
) -> ResponseAction:
    """
    Full pipeline to receive request, validate permissions, create action record,
    dispatch command to agent, and update tracking status.
    """
    # 1. Validate permissions and device
    device = validate_response_request(db, device_id, initiated_by=initiated_by, user_role=user_role)

    # 2. Create ResponseAction record
    action = create_response_action(
        db=db,
        device_id=device_id,
        action_type=action_type,
        alert_id=alert_id,
        initiated_by=initiated_by,
        parameters=parameters
    )

    # 3. Mark status as RUNNING and dispatch
    action.status = ResponseActionStatus.RUNNING
    db.add(action)
    db.commit()
    db.refresh(action)

    dispatch_success = dispatch_command_to_agent(action, device, db=db)
    if dispatch_success:
        result_msg = f"Command '{action_type}' dispatched to agent on host '{device.hostname}'."
        update_response_action_status(db, action.id, ResponseActionStatus.SUCCESS, result=result_msg)
    else:
        result_msg = f"Failed to dispatch command '{action_type}' to agent on host '{device.hostname}'."
        update_response_action_status(db, action.id, ResponseActionStatus.FAILED, result=result_msg)

    db.refresh(action)
    return action


def retry_response_action(db: Session, action_id: UUID) -> Optional[ResponseAction]:
    """
    Retries execution of a failed response action by re-dispatching to agent.
    """
    action = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not action:
        logger.error(f"[ResponseEngine] Cannot retry. Action ID {action_id} not found.")
        return None

    device = db.query(Device).filter(Device.id == action.device_id).first()
    if not device:
        logger.error(f"[ResponseEngine] Target device for action {action_id} not found.")
        return None

    action.status = ResponseActionStatus.RUNNING
    action.completed_at = None
    action.result = "Retrying command execution..."
    db.add(action)
    db.commit()
    db.refresh(action)

    dispatch_success = dispatch_command_to_agent(action, device, db=db)
    if dispatch_success:
        result_msg = f"Retried command '{action.action_type}' dispatched to host '{device.hostname}'."
        return update_response_action_status(db, action.id, ResponseActionStatus.SUCCESS, result=result_msg)
    else:
        result_msg = f"Retry failed: could not dispatch command '{action.action_type}' to host '{device.hostname}'."
        return update_response_action_status(db, action.id, ResponseActionStatus.FAILED, result=result_msg)


def cancel_response_action(db: Session, action_id: UUID) -> Optional[ResponseAction]:
    """
    Cancels a pending or running response action.
    """
    action = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not action:
        logger.error(f"[ResponseEngine] Cannot cancel. Action ID {action_id} not found.")
        return None

    action.status = ResponseActionStatus.CANCELLED
    action.completed_at = datetime.now(timezone.utc)
    action.result = "Action cancelled by operator."

    db.add(action)
    db.commit()
    db.refresh(action)

    logger.info(f"[ResponseEngine AUDIT] Action ID {action_id} cancelled by operator.")
    
    broadcast_payload = {
        "event": "RESPONSE_STATUS_UPDATE",
        "data": {
            "action_id": str(action.id),
            "device_id": str(action.device_id),
            "action_type": action.action_type.value,
            "status": action.status.value,
            "result": action.result,
            "completed_at": action.completed_at.isoformat()
        }
    }
    try:
        websocket_manager.broadcast_sync(broadcast_payload)
    except Exception as e:
        logger.warning(f"[ResponseEngine] Failed to broadcast cancel status update: {e}")

    return action


def get_response_action_by_id(db: Session, action_id: UUID) -> Optional[ResponseAction]:
    """Retrieves a single ResponseAction by UUID."""
    return db.query(ResponseAction).filter(ResponseAction.id == action_id).first()


def get_response_actions(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    device_id: Optional[UUID] = None,
    alert_id: Optional[UUID] = None,
    status: Optional[ResponseActionStatus] = None
) -> List[ResponseAction]:
    """Retrieves response actions with pagination and optional filtering."""
    query = db.query(ResponseAction)
    if device_id:
        query = query.filter(ResponseAction.device_id == device_id)
    if alert_id:
        query = query.filter(ResponseAction.alert_id == alert_id)
    if status:
        query = query.filter(ResponseAction.status == status)

    return query.order_by(ResponseAction.started_at.desc()).offset(skip).limit(limit).all()


def get_audit_logs_by_action_id(db: Session, action_id: UUID) -> List[ResponseAuditLog]:
    """Retrieves forensic audit log entries for a response action ordered chronologically."""
    return (
        db.query(ResponseAuditLog)
        .filter(ResponseAuditLog.action_id == action_id)
        .order_by(ResponseAuditLog.timestamp.asc())
        .all()
    )
