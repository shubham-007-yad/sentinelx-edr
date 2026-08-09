import uuid
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.models.investigation_case import CaseSeverity, CaseStatus
from app.schemas.investigation_case import (
    InvestigationCaseCreate,
    InvestigationCaseUpdate,
    CaseNoteCreate,
    CaseEvidenceCreate
)
from app.services import investigation_case_service


def test_full_case_management_lifecycle():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        init_db(db)
        corr_id = str(uuid.uuid4())

        # 1. Open case
        case_in = InvestigationCaseCreate(
            title="APT29 Suspicious Execution Case",
            severity=CaseSeverity.HIGH,
            status=CaseStatus.OPEN,
            assigned_to="Analyst_Unassigned",
            correlation_id=corr_id,
            summary="Initial detection of suspicious powershell execution."
        )
        case = investigation_case_service.create_investigation_case(db, case_in)

        assert case is not None
        assert case.id is not None
        assert case.title == "APT29 Suspicious Execution Case"
        assert case.status == CaseStatus.OPEN
        assert case.assigned_to == "Analyst_Unassigned"

        case_id = case.id

        # 2. Assign analyst & Change status to IN_PROGRESS
        update_in_progress = InvestigationCaseUpdate(
            assigned_to="Lead_Analyst_Sarah",
            status=CaseStatus.IN_PROGRESS,
            summary="Sarah investigating C2 traffic and powershell process lineage."
        )
        updated_case = investigation_case_service.update_investigation_case(db, case_id, update_in_progress)

        assert updated_case.assigned_to == "Lead_Analyst_Sarah"
        assert updated_case.status == CaseStatus.IN_PROGRESS

        # 3. Add notes
        note1_in = CaseNoteCreate(
            author="Lead_Analyst_Sarah",
            note_text="Confirmed suspicious outbound C2 IP 198.51.100.99 from powershell.exe"
        )
        note1 = investigation_case_service.add_case_note(db, case_id, note1_in)
        assert note1 is not None
        assert note1.author == "Lead_Analyst_Sarah"
        assert "198.51.100.99" in note1.note_text

        # 4. Attach evidence
        evidence_in = CaseEvidenceCreate(
            evidence_type="FILE_HASH",
            title="Malicious PowerShell Payload Hash",
            description="SHA-256 hash of obfuscated powershell payload script",
            file_path_or_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            added_by="Lead_Analyst_Sarah"
        )
        evidence = investigation_case_service.add_case_evidence(db, case_id, evidence_in)
        assert evidence is not None
        assert evidence.file_path_or_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        # 5. Link alerts
        alert_id_1 = str(uuid.uuid4())
        alert_id_2 = str(uuid.uuid4())
        linked_alerts_case = investigation_case_service.link_alerts_to_case(db, case_id, [alert_id_1, alert_id_2])
        assert alert_id_1 in linked_alerts_case.linked_alert_ids
        assert alert_id_2 in linked_alerts_case.linked_alert_ids

        # 6. Link telemetry
        telemetry_id_1 = str(uuid.uuid4())
        linked_telem_case = investigation_case_service.link_telemetry_to_case(db, case_id, [telemetry_id_1])
        assert telemetry_id_1 in linked_telem_case.linked_telemetry_ids

        # 7. Close case
        update_closed = InvestigationCaseUpdate(
            status=CaseStatus.CLOSED,
            summary="Case closed. Host isolated and process killed."
        )
        closed_case = investigation_case_service.update_investigation_case(db, case_id, update_closed)
        assert closed_case.status == CaseStatus.CLOSED
        assert closed_case.closed_at is not None

        # Verify get_case_by_id returns all linked notes and evidence
        fetched_case = investigation_case_service.get_case_by_id(db, case_id)
        assert fetched_case is not None
        assert len(fetched_case.notes) >= 1
        assert len(fetched_case.evidence_items) >= 1

    finally:
        db.close()
