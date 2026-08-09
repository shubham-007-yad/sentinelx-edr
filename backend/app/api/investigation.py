import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.api.deps import get_current_analyst, get_current_viewer
from app.models.user import User
from app.schemas.timeline import (
    UnifiedTimelineResponse,
    CorrelatedSequenceIngest
)
from app.schemas.threat_hunting import (
    ThreatHuntingQuery,
    ThreatHuntingResponse
)
from app.schemas.investigation_case import (
    InvestigationCaseCreate,
    InvestigationCaseUpdate,
    InvestigationCaseOut,
    CaseNoteCreate,
    CaseNoteOut,
    CaseEvidenceCreate,
    CaseEvidenceOut,
    LinkAlertsPayload,
    LinkTelemetryPayload
)
from app.models.investigation_case import CaseStatus
from app.services import timeline_engine, threat_hunting_engine, investigation_case_service

router = APIRouter(prefix="/investigation", tags=["Investigation & Threat Hunting Engine"])


@router.get("/dashboard-summary")
def get_investigations_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    """
    Returns aggregated metrics and data for the /investigations dashboard sections.
    """
    return investigation_case_service.get_dashboard_summary(db)


@router.get("/cases", response_model=List[InvestigationCaseOut])
def list_investigation_cases(
    status: Optional[CaseStatus] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    """List investigation cases filtered by status."""
    return investigation_case_service.get_investigation_cases(db, status=status, limit=limit)


@router.get("/cases/{case_id}", response_model=InvestigationCaseOut)
def get_investigation_case_detail(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    """Retrieve full details for a single investigation case."""
    db_case = investigation_case_service.get_case_by_id(db, case_id)
    if not db_case:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return db_case


@router.post("/cases", response_model=InvestigationCaseOut, status_code=status.HTTP_201_CREATED)
def create_investigation_case(
    payload: InvestigationCaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """Create a new investigation case (Analyst/Admin only)."""
    return investigation_case_service.create_investigation_case(db, payload)


@router.patch("/cases/{case_id}", response_model=InvestigationCaseOut)
def update_investigation_case(
    case_id: uuid.UUID,
    payload: InvestigationCaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """Update status, assignment, or summary for an existing investigation case."""
    updated = investigation_case_service.update_investigation_case(db, case_id, payload)
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return updated


@router.post("/cases/{case_id}/notes", response_model=CaseNoteOut, status_code=status.HTTP_201_CREATED)
def add_note_to_case(
    case_id: uuid.UUID,
    payload: CaseNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """Add an analyst note to a case."""
    if not payload.author:
        payload.author = current_user.username
    note = investigation_case_service.add_case_note(db, case_id, payload)
    if not note:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return note


@router.post("/cases/{case_id}/evidence", response_model=CaseEvidenceOut, status_code=status.HTTP_201_CREATED)
def attach_evidence_to_case(
    case_id: uuid.UUID,
    payload: CaseEvidenceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """Attach evidence item to a case."""
    if not payload.added_by:
        payload.added_by = current_user.username
    evidence = investigation_case_service.add_case_evidence(db, case_id, payload)
    if not evidence:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return evidence


@router.post("/cases/{case_id}/link-alerts", response_model=InvestigationCaseOut)
def link_alerts_to_case(
    case_id: uuid.UUID,
    payload: LinkAlertsPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """Link alert IDs to an investigation case."""
    updated = investigation_case_service.link_alerts_to_case(db, case_id, payload.alert_ids)
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return updated


@router.post("/cases/{case_id}/link-telemetry", response_model=InvestigationCaseOut)
def link_telemetry_to_case(
    case_id: uuid.UUID,
    payload: LinkTelemetryPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """Link telemetry IDs / correlation IDs to an investigation case."""
    updated = investigation_case_service.link_telemetry_to_case(db, case_id, payload.telemetry_ids)
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return updated


@router.get("/timeline/{correlation_id}", response_model=UnifiedTimelineResponse)
def get_investigation_timeline(
    correlation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_viewer)
):
    """
    Retrieve a unified, chronological telemetry timeline for a given correlation_id.
    """
    timeline_res = timeline_engine.get_unified_timeline(db, correlation_id)
    return timeline_res


@router.post("/timeline/sequence", response_model=UnifiedTimelineResponse)
def ingest_correlated_timeline_sequence(
    payload: CorrelatedSequenceIngest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """
    Ingest a sequence of correlated telemetry events sharing the same correlation_id.
    """
    correlation_id = payload.correlation_id or str(uuid.uuid4())
    timeline_res = timeline_engine.ingest_correlated_sequence(
        db=db,
        device_id=payload.device_id,
        correlation_id=correlation_id,
        events=payload.events
    )
    return timeline_res


@router.post("/hunt", response_model=ThreatHuntingResponse)
def execute_threat_hunting_query(
    query_payload: ThreatHuntingQuery,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """
    Execute a flexible threat hunting query across all telemetry streams (Analyst/Admin only).
    """
    return threat_hunting_engine.execute_threat_hunt(db, query_payload)


@router.get("/hunt", response_model=ThreatHuntingResponse)
def get_threat_hunting_query(
    query: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    process: Optional[str] = Query(None),
    sha256: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    min_severity: Optional[str] = Query(None),
    correlation_id: Optional[str] = Query(None),
    time_range_hours: Optional[float] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    """
    GET interface for flexible threat hunting queries (Analyst/Admin only).
    """
    h_query = ThreatHuntingQuery(
        query=query,
        device_id=device_id,
        hostname=hostname,
        username=username,
        process=process,
        sha256=sha256,
        ip=ip,
        domain=domain,
        threat_type=threat_type,
        min_severity=min_severity,
        correlation_id=correlation_id,
        time_range_hours=time_range_hours,
        limit=limit,
        offset=offset
    )
    return threat_hunting_engine.execute_threat_hunt(db, h_query)


from app.detection.behavior.incident_correlator import IncidentCorrelationEngine
incident_correlator_instance = IncidentCorrelationEngine()


@router.get("/correlated-incidents")
def list_unified_correlated_incidents(
    device_id: Optional[str] = Query(None),
    current_user: User = Depends(get_current_viewer)
):
    """
    Returns unified multi-vector incidents that correlate alerts.
    """
    return incident_correlator_instance.list_unified_incidents(device_id=device_id)


@router.get("/correlated-incidents/{correlation_id}")
def get_unified_correlated_incident(
    correlation_id: str,
    current_user: User = Depends(get_current_viewer)
):
    """
    Retrieves a single unified multi-vector incident by correlation_id.
    """
    incident = incident_correlator_instance.get_incident(correlation_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Unified correlated incident not found")
    return incident


from fastapi.responses import Response
from app.schemas.investigation_report import InvestigationReportData
from app.services import investigation_report_service


@router.get("/reports/json", response_model=InvestigationReportData)
def generate_investigation_report_json(
    case_id: Optional[uuid.UUID] = Query(None),
    correlation_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    report_data = investigation_report_service.generate_report_data(
        db=db,
        case_id=case_id,
        correlation_id=correlation_id,
        analyst_name=current_user.username
    )
    return report_data


@router.get("/reports/pdf")
def generate_investigation_report_pdf(
    case_id: Optional[uuid.UUID] = Query(None),
    correlation_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst)
):
    report_data = investigation_report_service.generate_report_data(
        db=db,
        case_id=case_id,
        correlation_id=correlation_id,
        analyst_name=current_user.username
    )
    pdf_bytes = investigation_report_service.export_report_pdf(report_data)
    filename = f"SentinelX_Report_{report_data.report_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
