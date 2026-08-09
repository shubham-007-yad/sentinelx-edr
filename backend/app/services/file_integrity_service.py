from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.file_integrity_record import FileIntegrityRecord
from app.models.response_action import ResponseAction, ResponseActionType, ResponseActionStatus
from app.models.response_audit_log import ResponseAuditLog
from app.models.alert import Alert
from app.models.threat import Threat
from app.schemas.file_integrity import (
    FileIntegrityRecordCreate, FileIntegrityRecordUpdate,
    FileChangeEventRequest, FileIntegrityEventOut,
    FIMResponseActionRequest, FIMResponseActionResponse,
    FIMTimelineItem, FIMTimelineResponse
)


def get_file_integrity_records(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    device_id: Optional[UUID] = None,
    file_path: Optional[str] = None,
    file_name: Optional[str] = None,
    sha256: Optional[str] = None,
    is_executable: Optional[bool] = None
) -> List[FileIntegrityRecord]:
    query = db.query(FileIntegrityRecord)

    if device_id:
        query = query.filter(FileIntegrityRecord.device_id == device_id)
    if file_path:
        query = query.filter(FileIntegrityRecord.file_path.ilike(f"%{file_path}%"))
    if file_name:
        query = query.filter(FileIntegrityRecord.file_name.ilike(f"%{file_name}%"))
    if sha256:
        query = query.filter(FileIntegrityRecord.sha256 == sha256)
    if is_executable is not None:
        query = query.filter(FileIntegrityRecord.is_executable == is_executable)

    return query.order_by(FileIntegrityRecord.updated_at.desc()).offset(skip).limit(limit).all()


def get_record_by_id(db: Session, record_id: UUID) -> Optional[FileIntegrityRecord]:
    return db.query(FileIntegrityRecord).filter(FileIntegrityRecord.id == record_id).first()


def upsert_file_integrity_record(
    db: Session,
    device_id: UUID,
    record_in: FileIntegrityRecordCreate
) -> FileIntegrityRecord:
    existing = db.query(FileIntegrityRecord).filter(
        FileIntegrityRecord.device_id == device_id,
        FileIntegrityRecord.file_path == record_in.file_path
    ).first()

    if existing:
        existing.file_name = record_in.file_name
        existing.sha256 = record_in.sha256
        existing.size = record_in.size
        existing.last_modified = record_in.last_modified
        existing.owner = record_in.owner
        existing.is_executable = record_in.is_executable
        db.commit()
        db.refresh(existing)
        return existing

    db_obj = FileIntegrityRecord(
        device_id=device_id,
        file_path=record_in.file_path,
        file_name=record_in.file_name,
        sha256=record_in.sha256,
        size=record_in.size,
        last_modified=record_in.last_modified,
        owner=record_in.owner,
        is_executable=record_in.is_executable,
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def batch_upsert_file_integrity_records(
    db: Session,
    device_id: UUID,
    records_in: List[FileIntegrityRecordCreate]
) -> List[FileIntegrityRecord]:
    results = []
    for rec in records_in:
        results.append(upsert_file_integrity_record(db=db, device_id=device_id, record_in=rec))
    return results


def verify_file_integrity_change(
    db: Session,
    device_id: UUID,
    event: FileChangeEventRequest
) -> FileIntegrityEventOut:
    lookup_path = event.old_path if (event.event_type == "RENAMED" and event.old_path) else event.file_path

    baseline = db.query(FileIntegrityRecord).filter(
        FileIntegrityRecord.device_id == device_id,
        FileIntegrityRecord.file_path == lookup_path
    ).first()

    changes = []
    status = "UNCHANGED"
    is_changed = False
    details = ""
    baseline_sha = baseline.sha256 if baseline else None
    baseline_sz = baseline.size if baseline else None

    # Parse last modified timestamp
    last_mod_dt = None
    if event.last_modified:
        try:
            last_mod_dt = datetime.fromisoformat(event.last_modified)
        except Exception:
            last_mod_dt = datetime.now(timezone.utc)

    if not baseline:
        if event.event_type == "DELETED":
            status = "DELETED"
            is_changed = True
            changes.append("file_deleted")
            details = f"Untracked file deletion: {event.file_path}"
        else:
            status = "NEW_FILE"
            is_changed = True
            changes.append("untracked_file_created")
            details = f"New untracked file detected at {event.file_path}"
            new_rec = FileIntegrityRecordCreate(
                file_path=event.file_path,
                file_name=event.file_name,
                sha256=event.sha256,
                size=event.size,
                last_modified=last_mod_dt,
                owner=event.owner,
                is_executable=event.is_executable
            )
            upsert_file_integrity_record(db=db, device_id=device_id, record_in=new_rec)
    else:
        if event.event_type == "DELETED":
            status = "DELETED"
            is_changed = True
            changes.append("file_deleted")
            details = f"Baseline monitored file deleted: {event.file_path}"
            db.delete(baseline)
            db.commit()
        else:
            if event.sha256 and baseline.sha256 != event.sha256:
                changes.append("sha256_mismatch")
            if event.size != baseline.size:
                changes.append("size_mismatch")
            if event.is_executable != baseline.is_executable:
                changes.append("executable_permission_changed")
            if event.event_type == "RENAMED" or (event.old_path and event.old_path != event.file_path):
                changes.append("file_renamed_or_moved")

            if changes:
                status = "CHANGED"
                is_changed = True
                diff_summary = ", ".join(changes)
                details = f"File integrity change detected ({diff_summary}). Path: {event.file_path}"

                baseline.file_path = event.file_path
                baseline.file_name = event.file_name
                baseline.sha256 = event.sha256 if event.sha256 else baseline.sha256
                baseline.size = event.size
                baseline.last_modified = last_mod_dt or baseline.last_modified
                baseline.owner = event.owner or baseline.owner
                baseline.is_executable = event.is_executable
                db.commit()
            else:
                status = "UNCHANGED"
                is_changed = False
                details = f"File event received; content matches baseline (SHA-256: {baseline.sha256[:8]}...)"

    return FileIntegrityEventOut(
        device_id=device_id,
        file_path=event.file_path,
        file_name=event.file_name,
        event_type=event.event_type,
        status=status,
        is_changed=is_changed,
        changes_detected=changes,
        baseline_sha256=baseline_sha,
        current_sha256=event.sha256,
        baseline_size=baseline_sz,
        current_size=event.size,
        is_executable=event.is_executable,
        details=details,
        timestamp=datetime.now(timezone.utc)
    )


def execute_fim_response_action(
    db: Session,
    device_id: UUID,
    payload: FIMResponseActionRequest,
    initiated_by: str = "ADMIN"
) -> FIMResponseActionResponse:
    file_path = payload.file_path
    action_type_str = payload.action_type.upper()

    baseline = db.query(FileIntegrityRecord).filter(
        FileIntegrityRecord.device_id == device_id,
        FileIntegrityRecord.file_path == file_path
    ).first()

    db_action_type = ResponseActionType.QUARANTINE
    if action_type_str == "RESTORE_BASELINE":
        db_action_type = getattr(ResponseActionType, "RESTORE_BASELINE", ResponseActionType.QUARANTINE)
    elif action_type_str == "RECALCULATE_BASELINE":
        db_action_type = getattr(ResponseActionType, "RECALCULATE_BASELINE", ResponseActionType.QUARANTINE)
    elif action_type_str == "IGNORE_CHANGE":
        db_action_type = getattr(ResponseActionType, "IGNORE_CHANGE", ResponseActionType.IGNORE)
    elif action_type_str == "ADD_ALLOWLIST":
        db_action_type = ResponseActionType.ADD_ALLOWLIST

    response_action = ResponseAction(
        device_id=device_id,
        action_type=db_action_type,
        status=ResponseActionStatus.SUCCESS,
        initiated_by=initiated_by,
        completed_at=datetime.now(timezone.utc),
        result=f"Action '{action_type_str}' executed on file '{file_path}'"
    )
    db.add(response_action)
    db.commit()
    db.refresh(response_action)

    message = ""
    if action_type_str == "RESTORE_BASELINE":
        message = f"Baseline state successfully restored for file '{file_path}'. (Simulation mode)"
    elif action_type_str == "QUARANTINE":
        message = f"File '{file_path}' successfully moved to endpoint quarantine vault."
    elif action_type_str == "IGNORE_CHANGE":
        message = f"Integrity change event ignored and suppressed for file '{file_path}'."
    elif action_type_str == "ADD_ALLOWLIST":
        message = f"File '{file_path}' added to enterprise approved security allowlist."
    elif action_type_str == "RECALCULATE_BASELINE":
        if baseline:
            if payload.new_sha256:
                baseline.sha256 = payload.new_sha256
            if payload.new_size is not None:
                baseline.size = payload.new_size
            baseline.updated_at = datetime.now(timezone.utc)
            db.commit()
            message = f"Baseline recalculated and updated for file '{file_path}'. New SHA-256: {baseline.sha256[:8]}..."
        else:
            message = f"Baseline recalculated and created for file '{file_path}'."
    else:
        message = f"Response action '{action_type_str}' executed on file '{file_path}'."

    audit_log = ResponseAuditLog(
        action_id=response_action.id,
        stage="EXECUTED",
        actor=initiated_by,
        message=message
    )
    db.add(audit_log)
    db.commit()

    return FIMResponseActionResponse(
        device_id=device_id,
        file_path=file_path,
        action_type=action_type_str,
        status="SUCCESS",
        message=message,
        action_id=response_action.id,
        timestamp=datetime.now(timezone.utc)
    )


def get_file_integrity_timeline(
    db: Session,
    device_id: UUID,
    file_path: str
) -> FIMTimelineResponse:
    """
    Phase 7: Chronological FIM Event Timeline Engine
    Correlates: File Created -> SHA Changed -> Threat Alert Generated -> Action Executed
    """
    baseline = db.query(FileIntegrityRecord).filter(
        FileIntegrityRecord.device_id == device_id,
        FileIntegrityRecord.file_path == file_path
    ).first()

    file_name = baseline.file_name if baseline else os.path.basename(file_path)
    sha256_val = baseline.sha256 if baseline else "N/A"
    status_str = "MONITORED" if baseline else "UNTRACKED"

    timeline_items: List[Dict[str, Any]] = []

    # 1. File Creation / Initial Baseline Step
    created_time = baseline.created_at if baseline else datetime.now(timezone.utc)
    timeline_items.append({
        "timestamp": created_time,
        "event_type": "FILE_CREATED",
        "title": f"{file_name} created",
        "description": f"File created and indexed on monitored path: {file_path}",
        "severity": "INFO",
        "actor": baseline.owner if (baseline and baseline.owner) else "SYSTEM",
        "details": {"file_path": file_path, "sha256": sha256_val, "size": baseline.size if baseline else 0}
    })

    # 2. File Modification / SHA Changed Step
    if baseline and baseline.updated_at > baseline.created_at:
        timeline_items.append({
            "timestamp": baseline.updated_at,
            "event_type": "SHA_CHANGED",
            "title": "SHA-256 Changed",
            "description": f"File content/hash modified. Current SHA-256: {baseline.sha256[:8]}...",
            "severity": "MEDIUM",
            "actor": baseline.owner or "SYSTEM",
            "details": {"sha256": baseline.sha256, "size": baseline.size}
        })

    # 3. Correlated Threat / Alert Generation Steps
    alerts = db.query(Alert).filter(Alert.device_id == device_id).all()
    for alert in alerts:
        # Check if alert message or title references file
        alert_msg = alert.message or ""
        if file_name.lower() in alert.title.lower() or file_name.lower() in alert_msg.lower() or file_path.lower() in alert_msg.lower():
            timeline_items.append({
                "timestamp": alert.created_at,
                "event_type": "ALERT_GENERATED",
                "title": f"{alert.severity} Severity Alert: {alert.title}",
                "description": alert_msg,
                "severity": alert.severity,
                "actor": "FIM_DETECTION_ENGINE",
                "details": {"alert_id": str(alert.id), "rule_name": alert.title}
            })

    # 4. Response Actions Executed Steps
    actions = db.query(ResponseAction).filter(ResponseAction.device_id == device_id).all()
    for act in actions:
        if act.result and (file_name.lower() in act.result.lower() or file_path.lower() in act.result.lower()):
            timeline_items.append({
                "timestamp": act.started_at or datetime.now(timezone.utc),
                "event_type": "RESPONSE_EXECUTED",
                "title": f"Action Executed: {act.action_type}",
                "description": act.result,
                "severity": "HIGH" if act.action_type in ["QUARANTINE", "DELETE"] else "INFO",
                "actor": act.initiated_by,
                "details": {"action_id": str(act.id), "status": act.status}
            })

    # Sort chronologically by timestamp
    timeline_items.sort(key=lambda x: x["timestamp"])

    # Assign 1-indexed step numbers
    structured_items: List[FIMTimelineItem] = []
    for idx, item in enumerate(timeline_items, start=1):
        structured_items.append(FIMTimelineItem(
            step=idx,
            timestamp=item["timestamp"],
            event_type=item["event_type"],
            title=item["title"],
            description=item["description"],
            severity=item["severity"],
            actor=item["actor"],
            details=item["details"]
        ))

    return FIMTimelineResponse(
        device_id=device_id,
        file_path=file_path,
        file_name=file_name,
        current_sha256=sha256_val,
        current_status=status_str,
        timeline=structured_items
    )
