import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session, joinedload

from app.models.investigation_case import (
    InvestigationCase,
    CaseSeverity,
    CaseStatus,
    CaseNote,
    CaseEvidence
)
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.response_action import ResponseAction
from app.models.device import Device
from app.schemas.investigation_case import (
    InvestigationCaseCreate,
    InvestigationCaseUpdate,
    CaseNoteCreate,
    CaseEvidenceCreate
)


def create_investigation_case(db: Session, case_in: InvestigationCaseCreate) -> InvestigationCase:
    """Creates a new InvestigationCase."""
    db_case = InvestigationCase(
        title=case_in.title,
        severity=case_in.severity,
        status=case_in.status,
        assigned_to=case_in.assigned_to,
        correlation_id=case_in.correlation_id or str(uuid.uuid4()),
        summary=case_in.summary,
        linked_alert_ids=[],
        linked_telemetry_ids=[]
    )
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    return db_case


def get_investigation_cases(
    db: Session,
    status: Optional[CaseStatus] = None,
    limit: int = 50
) -> List[InvestigationCase]:
    """Retrieves investigation cases optionally filtered by status."""
    query = db.query(InvestigationCase).options(
        joinedload(InvestigationCase.notes),
        joinedload(InvestigationCase.evidence_items)
    )
    if status:
        query = query.filter(InvestigationCase.status == status)
    return query.order_by(InvestigationCase.created_at.desc()).limit(limit).all()


def get_case_by_id(db: Session, case_id: uuid.UUID) -> Optional[InvestigationCase]:
    """Retrieves a single case by ID with notes and evidence."""
    return db.query(InvestigationCase).options(
        joinedload(InvestigationCase.notes),
        joinedload(InvestigationCase.evidence_items)
    ).filter(InvestigationCase.id == case_id).first()


def update_investigation_case(
    db: Session,
    case_id: uuid.UUID,
    case_in: InvestigationCaseUpdate
) -> Optional[InvestigationCase]:
    """Updates an existing InvestigationCase (Status, Assignment, Title, Summary)."""
    db_case = get_case_by_id(db, case_id)
    if not db_case:
        return None

    update_data = case_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_case, field, value)

    if case_in.status == CaseStatus.CLOSED and not db_case.closed_at:
        db_case.closed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(db_case)
    return db_case


def add_case_note(db: Session, case_id: uuid.UUID, note_in: CaseNoteCreate) -> Optional[CaseNote]:
    """Adds a analyst note to a case."""
    db_case = get_case_by_id(db, case_id)
    if not db_case:
        return None

    note = CaseNote(
        case_id=case_id,
        author=note_in.author or "Analyst",
        note_text=note_in.note_text
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


def add_case_evidence(db: Session, case_id: uuid.UUID, evidence_in: CaseEvidenceCreate) -> Optional[CaseEvidence]:
    """Attaches an evidence item to a case."""
    db_case = get_case_by_id(db, case_id)
    if not db_case:
        return None

    evidence = CaseEvidence(
        case_id=case_id,
        evidence_type=evidence_in.evidence_type,
        title=evidence_in.title,
        description=evidence_in.description,
        file_path_or_hash=evidence_in.file_path_or_hash,
        added_by=evidence_in.added_by or "Analyst"
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def link_alerts_to_case(db: Session, case_id: uuid.UUID, alert_ids: List[str]) -> Optional[InvestigationCase]:
    """Links alert IDs to a case."""
    db_case = get_case_by_id(db, case_id)
    if not db_case:
        return None

    current_alerts = set(db_case.linked_alert_ids or [])
    for aid in alert_ids:
        current_alerts.add(aid)

    db_case.linked_alert_ids = list(current_alerts)
    db.commit()
    db.refresh(db_case)
    return db_case


def link_telemetry_to_case(db: Session, case_id: uuid.UUID, telemetry_ids: List[str]) -> Optional[InvestigationCase]:
    """Links telemetry log IDs / correlation IDs to a case."""
    db_case = get_case_by_id(db, case_id)
    if not db_case:
        return None

    current_telem = set(db_case.linked_telemetry_ids or [])
    for tid in telemetry_ids:
        current_telem.add(tid)

    db_case.linked_telemetry_ids = list(current_telem)
    db.commit()
    db.refresh(db_case)
    return db_case


def get_dashboard_summary(db: Session) -> Dict[str, Any]:
    """
    Aggregates data for the /investigations dashboard sections:
    1. Open Cases
    2. Recent Incidents
    3. IOC Matches
    4. Response Actions
    5. Related Devices
    """
    open_cases = db.query(InvestigationCase).options(
        joinedload(InvestigationCase.notes),
        joinedload(InvestigationCase.evidence_items)
    ).filter(
        InvestigationCase.status.in_([CaseStatus.OPEN, CaseStatus.IN_PROGRESS])
    ).order_by(InvestigationCase.created_at.desc()).limit(10).all()

    recent_threats = db.query(Threat).order_by(Threat.detected_at.desc()).limit(10).all()
    recent_responses = db.query(ResponseAction).order_by(ResponseAction.started_at.desc()).limit(10).all()
    active_devices = db.query(Device).order_by(Device.last_seen.desc()).limit(10).all()

    return {
        "open_cases_count": len(open_cases),
        "open_cases": open_cases,
        "recent_incidents": [
            {
                "id": str(t.id),
                "title": t.rule_name,
                "threat_type": str(t.threat_type),
                "severity": str(t.severity.value) if hasattr(t.severity, "value") else str(t.severity),
                "status": str(t.status.value) if hasattr(t.status, "value") else str(t.status),
                "created_at": t.detected_at,
                "device_id": str(t.device_id) if hasattr(t, "device_id") and t.device_id else None
            }
            for t in recent_threats
        ],
        "response_actions": [
            {
                "id": str(r.id),
                "action_type": str(r.action_type.value) if hasattr(r.action_type, "value") else str(r.action_type),
                "status": str(r.status.value) if hasattr(r.status, "value") else str(r.status),
                "details": r.result or "Automated response action",
                "created_at": r.started_at,
                "device_id": str(r.device_id) if r.device_id else None
            }
            for r in recent_responses
        ],
        "related_devices": [
            {
                "id": str(d.id),
                "hostname": d.hostname,
                "ip_address": d.ip_address,
                "os_type": str(d.os_type.value) if hasattr(d.os_type, "value") else str(d.os_type),
                "status": str(d.status.value) if hasattr(d.status, "value") else str(d.status),
                "last_seen": d.last_seen
            }
            for d in active_devices
        ]
    }
