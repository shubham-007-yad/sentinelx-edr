import logging
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.device import Device, DeviceStatus, CommandStatus
from app.models.user import User
from app.models.agent_command import AgentCommand, AgentCommandType, AgentCommandStatus, AgentCommandAuditLog
from app.schemas.agent_command import AgentCommandCreate, AgentCommandAcknowledgeRequest
from app.core.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)


def _create_audit_log(
    db: Session,
    command: AgentCommand,
    issuer_username: str,
    details: str
) -> AgentCommandAuditLog:
    audit_entry = AgentCommandAuditLog(
        command_id=command.id,
        device_id=command.device_id,
        issuer_username=issuer_username,
        command_type=command.command_type.value if hasattr(command.command_type, "value") else str(command.command_type),
        status=command.status.value if hasattr(command.status, "value") else str(command.status),
        details=details
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry


def queue_command(
    db: Session,
    device_id: UUID,
    command_type: AgentCommandType,
    payload: Optional[Dict[str, Any]] = None,
    issuer: Optional[User] = None
) -> AgentCommand:
    """
    1. Validate target device exists
    2. Enqueue command in PENDING status
    3. Update device last_command_status to PENDING
    4. Create persistent audit log entry
    5. Broadcast command event over WebSocket
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise ValueError(f"Device with ID '{device_id}' was not found.")

    now = datetime.now(timezone.utc)
    cmd = AgentCommand(
        device_id=device_id,
        issuer_id=issuer.id if issuer else None,
        command_type=command_type,
        status=AgentCommandStatus.PENDING,
        payload=payload or {},
        queued_at=now
    )
    db.add(cmd)

    device.last_command_status = CommandStatus.PENDING
    device.updated_at = now
    db.add(device)

    db.commit()
    db.refresh(cmd)

    issuer_name = issuer.username if issuer else "SYSTEM"
    _create_audit_log(
        db=db,
        command=cmd,
        issuer_username=issuer_name,
        details=f"Command '{command_type.value}' queued for device {device.hostname}."
    )

    try:
        websocket_manager.broadcast_sync({
            "event": "AGENT_COMMAND_QUEUED",
            "data": {
                "command_id": str(cmd.id),
                "device_id": str(device.id),
                "hostname": device.hostname,
                "command_type": cmd.command_type.value,
                "status": cmd.status.value,
                "queued_at": cmd.queued_at.isoformat()
            }
        })
    except Exception as ws_err:
        logger.warning(f"Failed to broadcast AGENT_COMMAND_QUEUED over WebSocket: {ws_err}")

    return cmd


def queue_batch_commands(
    db: Session,
    device_ids: List[UUID],
    command_type: AgentCommandType,
    payload: Optional[Dict[str, Any]] = None,
    issuer: Optional[User] = None
) -> List[AgentCommand]:
    """
    Queues a remote command across multiple target devices.
    """
    queued_list: List[AgentCommand] = []
    for dev_id in device_ids:
        try:
            cmd = queue_command(db, dev_id, command_type, payload, issuer)
            queued_list.append(cmd)
        except Exception as err:
            logger.error(f"Failed to queue command for device {dev_id}: {err}")
    return queued_list


def get_pending_commands_for_device(db: Session, device_id: UUID) -> List[AgentCommand]:
    """
    Fetches PENDING commands for an agent endpoint, marks them DISPATCHED, and records dispatched timestamp.
    """
    pending = db.query(AgentCommand).filter(
        AgentCommand.device_id == device_id,
        AgentCommand.status == AgentCommandStatus.PENDING
    ).order_by(AgentCommand.queued_at.asc()).all()

    now = datetime.now(timezone.utc)
    for cmd in pending:
        cmd.status = AgentCommandStatus.DISPATCHED
        cmd.dispatched_at = now
        db.add(cmd)

    if pending:
        device = db.query(Device).filter(Device.id == device_id).first()
        if device:
            device.last_command_status = CommandStatus.DISPATCHED
            device.updated_at = now
            db.add(device)
        db.commit()

        for cmd in pending:
            db.refresh(cmd)

    return pending


def acknowledge_command(
    db: Session,
    ack_in: AgentCommandAcknowledgeRequest
) -> AgentCommand:
    """
    1. Validates command ID
    2. Updates command status to SUCCESS or FAILED
    3. Records output, error message, duration, and acknowledged_at timestamp
    4. Updates device last_command_status to EXECUTED or FAILED
    5. Audits execution completion in audit logs
    6. Broadcasts WS notification
    """
    cmd = db.query(AgentCommand).filter(AgentCommand.id == ack_in.command_id).first()
    if not cmd:
        raise ValueError(f"Agent command with ID '{ack_in.command_id}' was not found.")

    now = datetime.now(timezone.utc)
    cmd.status = ack_in.status
    cmd.result_output = ack_in.result_output
    cmd.error_message = ack_in.error_message
    cmd.execution_duration_ms = ack_in.execution_duration_ms
    cmd.acknowledged_at = now
    db.add(cmd)

    device = db.query(Device).filter(Device.id == cmd.device_id).first()
    if device:
        if ack_in.status == AgentCommandStatus.SUCCESS:
            device.last_command_status = CommandStatus.EXECUTED
        else:
            device.last_command_status = CommandStatus.FAILED
        device.updated_at = now
        db.add(device)

    db.commit()
    db.refresh(cmd)

    issuer_name = cmd.issuer.username if cmd.issuer else "SYSTEM"
    _create_audit_log(
        db=db,
        command=cmd,
        issuer_username=issuer_name,
        details=f"Command '{cmd.command_type.value}' acknowledged with status '{cmd.status.value}'. Duration: {cmd.execution_duration_ms or 0}ms."
    )

    try:
        websocket_manager.broadcast_sync({
            "event": "AGENT_COMMAND_ACKNOWLEDGED",
            "data": {
                "command_id": str(cmd.id),
                "device_id": str(cmd.device_id),
                "hostname": device.hostname if device else str(cmd.device_id),
                "command_type": cmd.command_type.value,
                "status": cmd.status.value,
                "result_output": cmd.result_output,
                "error_message": cmd.error_message,
                "duration_ms": cmd.execution_duration_ms,
                "acknowledged_at": cmd.acknowledged_at.isoformat() if cmd.acknowledged_at else now.isoformat()
            }
        })
    except Exception as ws_err:
        logger.warning(f"Failed to broadcast AGENT_COMMAND_ACKNOWLEDGED over WebSocket: {ws_err}")

    return cmd


def get_command_history(
    db: Session,
    device_id: Optional[UUID] = None,
    skip: int = 0,
    limit: int = 100
) -> List[AgentCommand]:
    """
    Retrieves command history with optional device filtering and pagination.
    """
    query = db.query(AgentCommand)
    if device_id:
        query = query.filter(AgentCommand.device_id == device_id)
    return query.order_by(AgentCommand.queued_at.desc()).offset(skip).limit(limit).all()


def get_command_audit_logs(
    db: Session,
    device_id: Optional[UUID] = None,
    skip: int = 0,
    limit: int = 100
) -> List[AgentCommandAuditLog]:
    """
    Retrieves audit trail logs for all issued agent commands.
    """
    query = db.query(AgentCommandAuditLog)
    if device_id:
        query = query.filter(AgentCommandAuditLog.device_id == device_id)
    return query.order_by(AgentCommandAuditLog.created_at.desc()).offset(skip).limit(limit).all()
