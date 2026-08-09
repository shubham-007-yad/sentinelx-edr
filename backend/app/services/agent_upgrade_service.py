from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.device import Device
from app.models.agent_upgrade import AgentUpgradeRecord, AgentUpgradeStatus, RollbackStatus
from app.schemas.agent_upgrade import AgentUpgradeStepUpdateRequest


def trigger_agent_upgrades(
    db: Session,
    device_ids: List[UUID],
    target_version: str = "1.2.0"
) -> List[AgentUpgradeRecord]:
    """
    Triggers an agent upgrade workflow from current_version to target_version.
    """
    records: List[AgentUpgradeRecord] = []

    for dev_id in device_ids:
        device = db.query(Device).filter(Device.id == dev_id).first()
        if not device:
            continue

        current_ver = device.agent_version or "1.0.0"
        init_log = f"[INFO] {datetime.now(timezone.utc).isoformat()} - Upgrade initiated: {current_ver} -> {target_version}."

        rec = AgentUpgradeRecord(
            device_id=device.id,
            current_version=current_ver,
            target_version=target_version,
            status=AgentUpgradeStatus.AVAILABLE,
            rollback_status=RollbackStatus.NONE,
            progress_percent=0,
            logs=init_log,
            started_at=datetime.now(timezone.utc)
        )
        db.add(rec)
        records.append(rec)

    db.commit()
    for r in records:
        db.refresh(r)

    return records


def advance_upgrade_simulation_step(
    db: Session,
    upgrade_id: UUID
) -> AgentUpgradeRecord:
    """
    Advances an upgrade simulation step through the lifecycle:
    New Version Available (0%) -> Download (25%) -> Install (65%) -> Restart (90%) -> Report Success (100%)
    """
    rec = db.query(AgentUpgradeRecord).filter(AgentUpgradeRecord.id == upgrade_id).first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Upgrade record {upgrade_id} not found.")

    device = db.query(Device).filter(Device.id == rec.device_id).first()
    now_str = datetime.now(timezone.utc).isoformat()

    if rec.status == AgentUpgradeStatus.AVAILABLE:
        rec.status = AgentUpgradeStatus.DOWNLOADING
        rec.progress_percent = 25
        rec.logs = (rec.logs or "") + f"\n[INFO] {now_str} - Downloading release binary package v{rec.target_version} (checksum verified)."
    elif rec.status == AgentUpgradeStatus.DOWNLOADING:
        rec.status = AgentUpgradeStatus.INSTALLING
        rec.progress_percent = 65
        rec.logs = (rec.logs or "") + f"\n[INFO] {now_str} - Staging & installing binary update v{rec.target_version} to daemon path."
    elif rec.status == AgentUpgradeStatus.INSTALLING:
        rec.status = AgentUpgradeStatus.RESTARTING
        rec.progress_percent = 90
        rec.logs = (rec.logs or "") + f"\n[INFO] {now_str} - Restarting SentinelX Agent daemon service into v{rec.target_version}."
    elif rec.status == AgentUpgradeStatus.RESTARTING:
        rec.status = AgentUpgradeStatus.SUCCESS
        rec.progress_percent = 100
        rec.completed_at = datetime.now(timezone.utc)
        rec.logs = (rec.logs or "") + f"\n[SUCCESS] {now_str} - Upgrade complete. Agent reported operational success on v{rec.target_version}."
        if device:
            device.agent_version = rec.target_version
            device.last_checkin = datetime.now(timezone.utc)
    elif rec.status == AgentUpgradeStatus.SUCCESS:
        # Already completed
        pass

    db.commit()
    db.refresh(rec)
    return rec


def rollback_agent_upgrade(
    db: Session,
    upgrade_id: UUID,
    target_rollback_version: Optional[str] = None
) -> AgentUpgradeRecord:
    """
    Rolls back an agent to its previous stable version.
    """
    rec = db.query(AgentUpgradeRecord).filter(AgentUpgradeRecord.id == upgrade_id).first()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Upgrade record {upgrade_id} not found.")

    device = db.query(Device).filter(Device.id == rec.device_id).first()
    now_str = datetime.now(timezone.utc).isoformat()

    rollback_ver = target_rollback_version or rec.current_version
    rec.rollback_status = RollbackStatus.SUCCESSFUL
    rec.status = AgentUpgradeStatus.ROLLED_BACK
    rec.completed_at = datetime.now(timezone.utc)
    rec.logs = (rec.logs or "") + f"\n[ROLLBACK] {now_str} - Rolled back agent daemon binary from v{rec.target_version} to v{rollback_ver}."

    if device:
        device.agent_version = rollback_ver
        device.last_checkin = datetime.now(timezone.utc)

    db.commit()
    db.refresh(rec)
    return rec


def get_upgrade_records(
    db: Session,
    device_id: Optional[UUID] = None,
    limit: int = 50
) -> List[AgentUpgradeRecord]:
    """
    Retrieves upgrade history records.
    """
    query = db.query(AgentUpgradeRecord)
    if device_id:
        query = query.filter(AgentUpgradeRecord.device_id == device_id)
    return query.order_by(AgentUpgradeRecord.started_at.desc()).limit(limit).all()
