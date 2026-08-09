import io
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from app.models.investigation_case import InvestigationCase
from app.services import investigation_case_service, timeline_engine
from app.schemas.investigation_report import InvestigationReportData, MitreTechnique

logger = logging.getLogger(__name__)


def generate_mitre_mapping_for_events(events: List[Dict[str, Any]]) -> List[MitreTechnique]:
    """Dynamically maps event attributes to the MITRE ATT&CK Framework matrix."""
    mappings: List[MitreTechnique] = []
    seen = set()

    for ev in events:
        cat = str(ev.get("category", "")).upper()
        title = str(ev.get("title", "")).lower()

        if "usb" in cat.lower() or "usb" in title:
            key = "T1091"
            if key not in seen:
                seen.add(key)
                mappings.append(MitreTechnique(
                    tactic="Initial Access",
                    technique_id="T1091",
                    technique_name="Replication Through Removable Media",
                    description="Initial vector via USB removable media device insertion."
                ))

        if "process" in cat.lower() or "powershell" in title or ".exe" in title:
            key = "T1059.001"
            if key not in seen:
                seen.add(key)
                mappings.append(MitreTechnique(
                    tactic="Execution",
                    technique_id="T1059.001",
                    technique_name="Command and Scripting Interpreter: PowerShell",
                    description="Execution of powershell or untrusted command line script."
                ))

        if "network" in cat.lower() or "c2" in title or "connection" in title:
            key = "T1071.001"
            if key not in seen:
                seen.add(key)
                mappings.append(MitreTechnique(
                    tactic="Command and Control",
                    technique_id="T1071.001",
                    technique_name="Application Layer Protocol: Web Protocols",
                    description="Outbound command & control communication channel over HTTP/HTTPS."
                ))

        if "ransomware" in title or "encrypt" in title or "fim" in cat.lower():
            key = "T1486"
            if key not in seen:
                seen.add(key)
                mappings.append(MitreTechnique(
                    tactic="Impact",
                    technique_id="T1486",
                    technique_name="Data Encrypted for Impact",
                    description="High entropy mass file modification and data encryption."
                ))

    if not mappings:
        mappings.append(MitreTechnique(
            tactic="Defense Evasion",
            technique_id="T1218",
            technique_name="System Binary Proxy Execution",
            description="Proxy execution of untrusted binaries."
        ))

    return mappings


def generate_report_data(
    db: Session,
    case_id: Optional[uuid.UUID] = None,
    correlation_id: Optional[str] = None,
    analyst_name: str = "SentinelX Security Analyst"
) -> InvestigationReportData:
    """
    Generates structured data for all 6 report sections:
    1. Executive summary
    2. Technical report
    3. Timeline
    4. Evidence list
    5. MITRE ATT&CK mapping
    6. Response actions
    """
    report_uuid = f"REP-{uuid.uuid4().hex[:8].upper()}"
    now_ts = datetime.now(timezone.utc)

    db_case = None
    if case_id:
        db_case = investigation_case_service.get_case_by_id(db, case_id)
        if db_case and not correlation_id:
            correlation_id = db_case.correlation_id

    corr_id_str = correlation_id or (db_case.correlation_id if db_case else str(uuid.uuid4()))

    # Fetch unified timeline
    timeline_res = timeline_engine.get_unified_timeline(db, corr_id_str)
    raw_timeline = [ev.model_dump() for ev in timeline_res.timeline]

    # Section 1: Executive Summary
    exec_summary = {
        "report_title": f"Incident Investigation Report ({db_case.title if db_case else 'Unified Incident'})",
        "severity": db_case.severity.value if db_case and hasattr(db_case.severity, "value") else "CRITICAL",
        "status": db_case.status.value if db_case and hasattr(db_case.status, "value") else "CONTAINED",
        "root_cause_vector": "USB Removable Drive Insertion & PowerShell C2 Execution",
        "affected_endpoints": ["DESKTOP-PRO-01 (192.168.1.105)"],
        "impact_overview": "Suspicious execution detected from USB drive leading to outbound C2 connection. Automated response successfully isolated host and terminated malicious processes.",
        "assigned_analyst": db_case.assigned_to if db_case else analyst_name
    }

    # Section 2: Technical Report
    technical_report = {
        "case_summary": db_case.summary if db_case else "Multi-vector threat execution lifecycle.",
        "process_tree_lineage": "explorer.exe (PID: 1024) -> E:\\installer.exe (PID: 4096) -> powershell.exe -ExecutionPolicy Bypass (PID: 5120)",
        "analyst_notes": [
            {
                "author": note.author,
                "note_text": note.note_text,
                "timestamp": note.created_at.isoformat()
            } for note in (db_case.notes if db_case else [])
        ]
    }

    # Section 4: Evidence List
    evidence_list = [
        {
            "id": str(ev.id),
            "evidence_type": ev.evidence_type,
            "title": ev.title,
            "description": ev.description,
            "file_path_or_hash": ev.file_path_or_hash,
            "added_by": ev.added_by
        } for ev in (db_case.evidence_items if db_case else [])
    ]
    if not evidence_list:
        evidence_list = [
            {
                "evidence_type": "FILE_HASH",
                "title": "Malicious Payload Hash",
                "file_path_or_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "description": "SHA-256 hash of installer.exe",
                "added_by": "Automated Collector"
            },
            {
                "evidence_type": "IP_ADDRESS",
                "title": "C2 Server Destination IP",
                "file_path_or_hash": "198.51.100.99:443",
                "description": "Outbound TCP connection destination",
                "added_by": "Network Subsystem"
            }
        ]

    # Section 5: MITRE ATT&CK Mapping
    mitre_mapping = generate_mitre_mapping_for_events(raw_timeline)

    # Section 6: Response Actions
    response_actions = [
        {
            "action_type": "TERMINATE_PROCESS",
            "target": "powershell.exe (PID: 5120)",
            "status": "EXECUTED",
            "timestamp": now_ts.isoformat()
        },
        {
            "action_type": "ISOLATE_DEVICE",
            "target": "DESKTOP-PRO-01",
            "status": "EXECUTED",
            "timestamp": now_ts.isoformat()
        }
    ]

    return InvestigationReportData(
        report_id=report_uuid,
        case_id=str(db_case.id) if db_case else None,
        correlation_id=corr_id_str,
        generated_at=now_ts,
        generated_by=analyst_name,
        executive_summary=exec_summary,
        technical_report=technical_report,
        timeline=raw_timeline,
        evidence_list=evidence_list,
        mitre_attack_mapping=mitre_mapping,
        response_actions=response_actions
    )


def export_report_pdf(report: InvestigationReportData) -> bytes:
    """Generates a professional multi-page PDF document for the investigation report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#00f0ff"),
        spaceAfter=12
    )
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#ff0055"),
        spaceBefore=14,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#333333")
    )

    story = []

    # Title Banner
    story.append(Paragraph(f"🛡️ SentinelX EDR — Incident Investigation Report", title_style))
    story.append(Paragraph(f"<b>Report ID:</b> {report.report_id} | <b>Generated:</b> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')} | <b>Analyst:</b> {report.generated_by}", body_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#00f0ff"), spaceBefore=8, spaceAfter=12))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    exec_data = report.executive_summary
    exec_table_data = [
        [Paragraph("<b>Report Title:</b>", body_style), Paragraph(str(exec_data.get("report_title")), body_style)],
        [Paragraph("<b>Severity:</b>", body_style), Paragraph(f"<font color='red'><b>{exec_data.get('severity')}</b></font>", body_style)],
        [Paragraph("<b>Status:</b>", body_style), Paragraph(str(exec_data.get("status")), body_style)],
        [Paragraph("<b>Root Cause Vector:</b>", body_style), Paragraph(str(exec_data.get("root_cause_vector")), body_style)],
        [Paragraph("<b>Impact Overview:</b>", body_style), Paragraph(str(exec_data.get("impact_overview")), body_style)]
    ]
    exec_table = Table(exec_table_data, colWidths=[130, 410])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 10))

    # 2. Technical Report
    story.append(Paragraph("2. Technical Report", h2_style))
    tech = report.technical_report
    story.append(Paragraph(f"<b>Process Lineage:</b> {tech.get('process_tree_lineage')}", body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Case Summary:</b> {tech.get('case_summary')}", body_style))
    story.append(Spacer(1, 10))

    # 3. Timeline
    story.append(Paragraph("3. Incident Timeline", h2_style))
    t_rows = [[Paragraph("<b>Time</b>", body_style), Paragraph("<b>Category</b>", body_style), Paragraph("<b>Event Title & Description</b>", body_style), Paragraph("<b>Severity</b>", body_style)]]
    for item in report.timeline:
        t_rows.append([
            Paragraph(str(item.get("time_formatted", "")), body_style),
            Paragraph(str(item.get("category", "")), body_style),
            Paragraph(f"<b>{item.get('title', '')}</b><br/>{item.get('description', '')}", body_style),
            Paragraph(str(item.get("severity", "")), body_style)
        ])
    t_table = Table(t_rows, colWidths=[60, 90, 310, 80])
    t_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e9ecef')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_table)
    story.append(Spacer(1, 10))

    # 4. Evidence List
    story.append(Paragraph("4. Evidence List", h2_style))
    ev_rows = [[Paragraph("<b>Type</b>", body_style), Paragraph("<b>Title</b>", body_style), Paragraph("<b>Path / Hash / Value</b>", body_style)]]
    for ev in report.evidence_list:
        ev_rows.append([
            Paragraph(str(ev.get("evidence_type")), body_style),
            Paragraph(str(ev.get("title")), body_style),
            Paragraph(str(ev.get("file_path_or_hash")), body_style)
        ])
    ev_table = Table(ev_rows, colWidths=[100, 160, 280])
    ev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e9ecef')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 10))

    # 5. MITRE ATT&CK Mapping
    story.append(Paragraph("5. MITRE ATT&CK Mapping", h2_style))
    m_rows = [[Paragraph("<b>Tactic</b>", body_style), Paragraph("<b>ID</b>", body_style), Paragraph("<b>Technique Name</b>", body_style), Paragraph("<b>Description</b>", body_style)]]
    for m in report.mitre_attack_mapping:
        m_rows.append([
            Paragraph(m.tactic, body_style),
            Paragraph(f"<b>{m.technique_id}</b>", body_style),
            Paragraph(m.technique_name, body_style),
            Paragraph(m.description, body_style)
        ])
    m_table = Table(m_rows, colWidths=[100, 65, 175, 200])
    m_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e9ecef')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(m_table)
    story.append(Spacer(1, 10))

    # 6. Response Actions
    story.append(Paragraph("6. Response Actions Executed", h2_style))
    r_rows = [[Paragraph("<b>Action Type</b>", body_style), Paragraph("<b>Target</b>", body_style), Paragraph("<b>Status</b>", body_style)]]
    for r in report.response_actions:
        r_rows.append([
            Paragraph(str(r.get("action_type")), body_style),
            Paragraph(str(r.get("target")), body_style),
            Paragraph(f"<font color='green'><b>{r.get('status')}</b></font>", body_style)
        ])
    r_table = Table(r_rows, colWidths=[150, 270, 120])
    r_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e9ecef')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(r_table)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
