import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_

from app.models.event_log import SecurityEvent, EventLevel, EventType
from app.models.device import Device
from app.detection.engine import DetectionEngine
from app.detection.event import DetectionEvent
from app.detection.pipeline import detection_pipeline

logger = logging.getLogger(__name__)
detection_engine = DetectionEngine()


def ingest_security_events(
    db: Session,
    device_id: uuid.UUID,
    raw_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Ingests raw OS security events from an agent, stores them in the database,
    evaluates authentication & privilege rules, and passes detections to the pipeline.
    """
    db_device = db.query(Device).filter(Device.id == device_id).first()
    if not db_device:
        logger.warning(f"[EventLogService] Ingest failed: Device '{device_id}' not found.")
        return {"status": "ERROR", "message": f"Device {device_id} not found", "ingested": 0}

    created_events: List[SecurityEvent] = []

    for raw in raw_events:
        try:
            # Parse level enum safely
            lvl_str = raw.get("level", "Information")
            try:
                level_enum = EventLevel(lvl_str)
            except Exception:
                level_enum = EventLevel.INFORMATION

            ts_str = raw.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            event_obj = SecurityEvent(
                id=uuid.UUID(raw["id"]) if "id" in raw and isinstance(raw["id"], str) else uuid.uuid4(),
                device_id=device_id,
                event_source=raw.get("event_source", "Security"),
                event_id=str(raw.get("event_id", "0")),
                event_type=raw.get("event_type", "SYSTEM_EVENT"),
                level=level_enum,
                username=raw.get("username"),
                domain=raw.get("domain"),
                computer=raw.get("computer", db_device.hostname),
                logon_type=raw.get("logon_type"),
                ip_address=raw.get("ip_address"),
                status=raw.get("status", "SUCCESS"),
                description=raw.get("description", "OS Event"),
                raw_event=raw.get("raw_event"),
                timestamp=ts
            )
            db.add(event_obj)
            created_events.append(event_obj)
        except Exception as err:
            logger.error(f"[EventLogService] Error parsing event payload: {err}")

    db.commit()

    # ----------------------------------------------------
    # Detection Engine Evaluation
    # ----------------------------------------------------
    evaluated_dicts = [e.raw_event or {
        "event_id": e.event_id,
        "event_type": e.event_type,
        "status": e.status,
        "username": e.username,
        "logon_type": e.logon_type,
        "ip_address": e.ip_address,
        "event_source": e.event_source
    } for e in created_events]

    rule_findings = detection_engine.evaluate_event_log_batch(evaluated_dicts)

    threat_count = 0
    for finding in rule_findings:
        detection_evt = DetectionEvent(
            source_subsystem="OS_EVENT",
            device_id=device_id,
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            threat_type=finding.threat_type.value,
            severity=finding.severity.value,
            description=finding.description,
            mitre_attack=finding.mitre_attack,
            confidence=finding.confidence,
            raw_payload={"finding": finding.rule_name, "details": finding.description}
        )
        pipeline_res = detection_pipeline.process_event(db=db, event=detection_evt)
        if pipeline_res and pipeline_res.get("threat_id"):
            threat_count += 1

    return {
        "status": "SUCCESS",
        "ingested": len(created_events),
        "threats_detected": threat_count
    }


def get_security_events(
    db: Session,
    device_id: Optional[uuid.UUID] = None,
    event_type: Optional[str] = None,
    level: Optional[str] = None,
    username: Optional[str] = None,
    search: Optional[str] = None,
    date_range: Optional[str] = None,
    skip: int = 0,
    limit: int = 50
) -> Dict[str, Any]:
    """Retrieves paginated and filtered SecurityEvent logs."""
    query = db.query(SecurityEvent)

    if device_id:
        query = query.filter(SecurityEvent.device_id == device_id)
    if event_type and event_type != "ALL":
        query = query.filter(SecurityEvent.event_type == event_type)
    if level and level != "ALL":
        query = query.filter(SecurityEvent.level == level)
    if username:
        query = query.filter(SecurityEvent.username.ilike(f"%{username}%"))
    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            or_(
                SecurityEvent.description.ilike(search_fmt),
                SecurityEvent.username.ilike(search_fmt),
                SecurityEvent.event_id.ilike(search_fmt),
                SecurityEvent.ip_address.ilike(search_fmt),
                SecurityEvent.computer.ilike(search_fmt),
                SecurityEvent.event_source.ilike(search_fmt)
            )
        )

    if date_range:
        now = datetime.now(timezone.utc)
        if date_range == "today":
            start_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
            query = query.filter(SecurityEvent.timestamp >= start_dt)
        elif date_range == "last_24h":
            start_dt = now.replace(day=now.day-1) if now.day > 1 else now
            query = query.filter(SecurityEvent.timestamp >= start_dt)
        elif date_range == "last_7d":
            from datetime import timedelta
            start_dt = now - timedelta(days=7)
            query = query.filter(SecurityEvent.timestamp >= start_dt)

    total = query.count()
    records = query.order_by(desc(SecurityEvent.timestamp)).offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": records,
        "skip": skip,
        "limit": limit
    }


def get_authentication_summary(
    db: Session,
    device_id: Optional[uuid.UUID] = None
) -> Dict[str, Any]:
    """
    Provides Phase 5 exact metrics:
    - Logins
    - Failed logins
    - Privilege changes
    - Persistence events
    - Critical events
    """
    query = db.query(SecurityEvent)
    if device_id:
        query = query.filter(SecurityEvent.device_id == device_id)

    total_events = query.count()

    logins = query.filter(
        SecurityEvent.event_type == "AUTHENTICATION_SUCCESS"
    ).count()

    failed_logons = query.filter(
        or_(
            SecurityEvent.event_type == "AUTHENTICATION_FAILURE",
            SecurityEvent.status == "FAILED"
        )
    ).count()

    privilege_changes = query.filter(
        or_(
            SecurityEvent.event_type.in_(["PRIVILEGE_ESCALATION", "ACCOUNT_MANAGEMENT"]),
            SecurityEvent.event_id.in_(["4672", "4720", "4732", "4728", "4725", "4740", "SUDO_EXEC", "GROUP_ADDED"])
        )
    ).count()

    persistence_events = query.filter(
        or_(
            SecurityEvent.event_type.in_(["PERSISTENCE", "FIM_STARTUP_MODIFICATION"]),
            SecurityEvent.event_id.in_(["4697", "4702", "4657", "4698", "7045", "TASK_CREATED", "SERVICE_CREATED", "REG_RUN_MODIFIED"])
        )
    ).count()

    critical_events = query.filter(
        or_(
            SecurityEvent.level == EventLevel.CRITICAL,
            SecurityEvent.event_type == "DEFENSE_EVASION",
            SecurityEvent.event_id.in_(["1102", "104", "LOG_CLEARED"])
        )
    ).count()

    return {
        "total_events": total_events,
        "logins": logins,
        "failed_logons": failed_logons,
        "privilege_changes": privilege_changes,
        "persistence_events": persistence_events,
        "critical_events": critical_events
    }



def get_auth_timeline(
    db: Session,
    device_id: Optional[uuid.UUID] = None,
    limit: int = 30
) -> List[Dict[str, Any]]:
    """Returns chronological timeline of logon and authentication events."""
    query = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_([
            "AUTHENTICATION_SUCCESS",
            "AUTHENTICATION_FAILURE",
            "PRIVILEGE_ESCALATION",
            "ACCOUNT_MANAGEMENT"
        ])
    )
    if device_id:
        query = query.filter(SecurityEvent.device_id == device_id)

    records = query.order_by(desc(SecurityEvent.timestamp)).limit(limit).all()

    timeline = []
    for r in records:
        is_remote = "10" in str(r.logon_type or "") or "Remote" in str(r.logon_type or "") or "SSH" in str(r.event_id or "")
        is_admin = (r.username or "").lower() in ["administrator", "root", "admin"] or r.event_id in ["4672", "SUDO_EXEC"]

        category = "USER_LOGIN"
        if r.event_type == "AUTHENTICATION_FAILURE" or r.status == "FAILED":
            category = "FAILED_AUTHENTICATION"
        elif is_remote:
            category = "REMOTE_LOGIN"
        elif is_admin:
            category = "ADMINISTRATOR_LOGIN"

        timeline.append({
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat(),
            "event_id": r.event_id,
            "event_type": r.event_type,
            "category": category,
            "username": r.username or "Unknown",
            "domain": r.domain,
            "logon_type": r.logon_type or "Interactive",
            "ip_address": r.ip_address or "Local",
            "status": r.status,
            "description": r.description
        })

    return timeline


def get_attack_chain_timeline(
    db: Session,
    device_id: Optional[uuid.UUID] = None,
    limit: int = 20
) -> List[Dict[str, Any]]:
    """
    Phase 7: Constructs structured step-by-step Attack Chain Timelines.
    Sequence: Failed Login ➔ Failed Login ➔ Administrator Login ➔ New Scheduled Task ➔ Critical Alert
    """
    query = db.query(SecurityEvent)
    if device_id:
        query = query.filter(SecurityEvent.device_id == device_id)

    records = query.order_by(SecurityEvent.timestamp.asc()).limit(limit).all()

    chain: List[Dict[str, Any]] = []
    step_num = 1

    for r in records:
        ts_fmt = r.timestamp.strftime("%H:%M")
        event_title = "OS Event"
        badge_type = "INFO"
        severity = r.level.value if hasattr(r.level, "value") else str(r.level)

        if r.event_type == "AUTHENTICATION_FAILURE" or r.status == "FAILED":
            event_title = "Failed Login"
            badge_type = "FAILED_LOGIN"
            severity = "Warning"
        elif r.event_type == "AUTHENTICATION_SUCCESS" and (r.username or "").lower() in ["administrator", "root", "admin"]:
            event_title = "Administrator Login"
            badge_type = "ADMIN_LOGIN"
            severity = "High"
        elif r.event_type == "AUTHENTICATION_SUCCESS":
            event_title = "Successful Login"
            badge_type = "USER_LOGIN"
        elif r.event_type == "PRIVILEGE_ESCALATION" or r.event_id in ["4672", "4732", "SUDO_EXEC"]:
            event_title = "Administrator Login"
            badge_type = "ADMIN_LOGIN"
            severity = "High"
        elif r.event_type == "PERSISTENCE" or r.event_id in ["4702", "4697", "4657"]:
            event_title = "New Scheduled Task" if "task" in r.description.lower() or r.event_id == "4702" else "New Windows Service"
            badge_type = "PERSISTENCE"
            severity = "High"
        elif r.event_type == "DEFENSE_EVASION" or r.level == EventLevel.CRITICAL:
            event_title = "Critical Alert"
            badge_type = "CRITICAL_ALERT"
            severity = "Critical"

        chain.append({
            "step": step_num,
            "time": ts_fmt,
            "timestamp": r.timestamp.isoformat(),
            "event_title": event_title,
            "badge_type": badge_type,
            "severity": severity,
            "user": r.username or "SYSTEM",
            "device": r.computer or "Endpoint",
            "event_id": r.event_id,
            "description": r.description,
            "source": r.event_source
        })
        step_num += 1

    return chain


def trigger_attack_chain_sequence(
    db: Session,
    device_id: uuid.UUID
) -> Dict[str, Any]:
    """
    Triggers the exact Phase 7 Attack Timeline sequence:
    02:10 — Failed Login ➔ 02:10 — Failed Login ➔ 02:11 — Administrator Login ➔ 02:12 — New Scheduled Task ➔ Critical Alert
    """
    ts_base = datetime.now(timezone.utc)
    ts_0210_1 = ts_base.replace(hour=2, minute=10, second=0).isoformat()
    ts_0210_2 = ts_base.replace(hour=2, minute=10, second=15).isoformat()
    ts_0211 = ts_base.replace(hour=2, minute=11, second=0).isoformat()
    ts_0212_1 = ts_base.replace(hour=2, minute=12, second=0).isoformat()
    ts_0212_2 = ts_base.replace(hour=2, minute=12, second=30).isoformat()

    sequence_events = [
        {
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "event_source": "Security",
            "event_id": "4625",
            "event_type": "AUTHENTICATION_FAILURE",
            "level": "Warning",
            "username": "Administrator",
            "computer": "CORP-DC01",
            "logon_type": "10-RemoteDesktop",
            "ip_address": "198.51.100.44",
            "status": "FAILED",
            "description": "Failed logon attempt #1 for Administrator from 198.51.100.44",
            "timestamp": ts_0210_1
        },
        {
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "event_source": "Security",
            "event_id": "4625",
            "event_type": "AUTHENTICATION_FAILURE",
            "level": "Warning",
            "username": "Administrator",
            "computer": "CORP-DC01",
            "logon_type": "10-RemoteDesktop",
            "ip_address": "198.51.100.44",
            "status": "FAILED",
            "description": "Failed logon attempt #2 for Administrator from 198.51.100.44",
            "timestamp": ts_0210_2
        },
        {
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "event_source": "Security",
            "event_id": "4672",
            "event_type": "PRIVILEGE_ESCALATION",
            "level": "Warning",
            "username": "Administrator",
            "computer": "CORP-DC01",
            "logon_type": "10-RemoteDesktop",
            "ip_address": "198.51.100.44",
            "status": "SUCCESS",
            "description": "Administrator Login: Special privileges assigned to new logon",
            "timestamp": ts_0211
        },
        {
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "event_source": "Security",
            "event_id": "4702",
            "event_type": "PERSISTENCE",
            "level": "Warning",
            "username": "Administrator",
            "computer": "CORP-DC01",
            "status": "SUCCESS",
            "description": "New Scheduled Task created: TaskName=\\Microsoft\\Windows\\Maintenance\\UpdaterSvc",
            "timestamp": ts_0212_1
        },
        {
            "id": str(uuid.uuid4()),
            "device_id": str(device_id),
            "event_source": "Security",
            "event_id": "1102",
            "event_type": "DEFENSE_EVASION",
            "level": "Critical",
            "username": "Administrator",
            "computer": "CORP-DC01",
            "status": "SUCCESS",
            "description": "Critical Alert: Security Audit Log Cleared (Anti-Forensics / Attack Chain Escalation)",
            "timestamp": ts_0212_2
        }
    ]

    res = ingest_security_events(db=db, device_id=device_id, raw_events=sequence_events)
    return {
        "status": "SUCCESS",
        "scenario": "PHASE_7_ATTACK_CHAIN",
        "steps_injected": len(sequence_events),
        "ingest_result": res
    }

