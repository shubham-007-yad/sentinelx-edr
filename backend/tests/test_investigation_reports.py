import uuid
import pytest
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.db.init_db import init_db
from app.schemas.investigation_case import InvestigationCaseCreate
from app.services import investigation_case_service, investigation_report_service


def test_investigation_report_generation_json_and_pdf():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        init_db(db)
        correlation_id = str(uuid.uuid4())

        # Setup test case
        case_in = InvestigationCaseCreate(
            title="APT Incident Report Test",
            severity="CRITICAL",
            summary="Multi-stage ransomware attack initiated via USB drive.",
            correlation_id=correlation_id
        )
        case = investigation_case_service.create_investigation_case(db, case_in)

        # 1. Generate Report Data
        report_data = investigation_report_service.generate_report_data(
            db=db,
            case_id=case.id,
            correlation_id=correlation_id,
            analyst_name="Test_Analyst"
        )

        assert report_data is not None
        assert report_data.report_id.startswith("REP-")

        # Verify 6 required sections:
        # Section 1: Executive Summary
        exec_summary = report_data.executive_summary
        assert exec_summary is not None
        assert "severity" in exec_summary
        assert "root_cause_vector" in exec_summary

        # Section 2: Technical Report
        tech_report = report_data.technical_report
        assert tech_report is not None
        assert "process_tree_lineage" in tech_report

        # Section 3: Timeline
        assert isinstance(report_data.timeline, list)

        # Section 4: Evidence List
        assert len(report_data.evidence_list) >= 1

        # Section 5: MITRE ATT&CK Mapping
        assert len(report_data.mitre_attack_mapping) >= 1
        tactics = [m.tactic for m in report_data.mitre_attack_mapping]
        assert any(t in ["Initial Access", "Execution", "Command and Control", "Impact", "Defense Evasion"] for t in tactics)

        # Section 6: Response Actions
        assert len(report_data.response_actions) >= 1

        # 2. Verify JSON export dictionary structure
        json_export = report_data.model_dump()
        assert "executive_summary" in json_export
        assert "mitre_attack_mapping" in json_export
        assert "response_actions" in json_export

        # 3. Verify PDF binary export
        pdf_bytes = investigation_report_service.export_report_pdf(report_data)
        assert pdf_bytes is not None
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF"), "PDF export output must be valid PDF binary starting with %PDF header"
        assert len(pdf_bytes) > 500

    finally:
        db.close()
