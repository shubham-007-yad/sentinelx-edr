"""
Executive & Technical Security Report Generation Engine
Supports Executive & Technical Reports in PDF, CSV, and JSON formats.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
import io
import csv
import logging

from sqlalchemy.orm import Session
from sqlalchemy import desc

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from app.analytics.aggregation import TelemetryAggregator
from app.analytics.metrics import BusinessMetricsCalculator
from app.analytics.trends import TrendAnalyzer
from app.analytics.mitre import MitreMapper

from app.models.alert import Alert
from app.models.threat import Threat, ThreatStatus
from app.models.device import Device
from app.models.response_action import ResponseAction
from app.models.usb_event import USBEvent
from app.models.network_connection import NetworkConnection
from app.models.process_audit_log import ProcessAuditLog
from app.models.event_log import SecurityEvent

logger = logging.getLogger(__name__)


class ExecutiveReporter:
    def __init__(self, db: Session):
        self.db = db
        self.aggregator = TelemetryAggregator(db)
        self.metrics_calc = BusinessMetricsCalculator(db)
        self.trend_analyzer = TrendAnalyzer(db)
        self.mitre_mapper = MitreMapper(db)

    # -------------------------------------------------------------------------
    # 1. EXECUTIVE REPORT PAYLOAD (JSON)
    # -------------------------------------------------------------------------
    def generate_executive_summary_report(self, timeframe_days: int = 7) -> Dict[str, Any]:
        """
        Generates Executive Report payload containing:
        - Executive Summary & Overall Risk Status
        - Key Performance Indicators (KPIs)
        - Threat Trends & Velocity
        - Endpoint Health Breakdown
        - Top Risks (Vulnerable Endpoints & Contributing Signals)
        """
        posture = self.metrics_calc.calculate_security_posture_overview(timeframe_days)
        severity_dist = self.aggregator.aggregate_alerts_by_severity()
        status_dist = self.aggregator.aggregate_alerts_by_status()
        risk_endpoints = self.metrics_calc.calculate_endpoint_risk_scores(timeframe_days)[:10]
        response_metrics = self.metrics_calc.calculate_response_time_metrics(timeframe_days)
        trend_velocity = self.trend_analyzer.get_trend_velocity(timeframe_days)
        mitre_data = self.mitre_mapper.analyze_mitre_attack_coverage(timeframe_days, limit_techniques=5)
        top_kpis = self.metrics_calc.calculate_top_executive_metrics()

        high_risk_endpoints_count = sum(1 for e in risk_endpoints if e["risk_score"] >= 60.0)
        total_alerts = sum(severity_dist.values())
        critical_alerts = severity_dist.get("CRITICAL", 0)

        if critical_alerts > 5 or high_risk_endpoints_count >= 3:
            org_risk_status = "ELEVATED RISK"
            org_risk_summary = "Action required: Multiple high-risk endpoints or critical incidents detected."
        elif critical_alerts > 0 or high_risk_endpoints_count > 0:
            org_risk_status = "MODERATE RISK"
            org_risk_summary = "Active monitoring: Low-to-moderate threats identified in environment."
        else:
            org_risk_status = "LOW RISK"
            org_risk_summary = "Optimal security posture: Minimal critical threat activity observed."

        return {
            "report_type": "EXECUTIVE_REPORT",
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "timeframe_days": timeframe_days,
            "executive_summary": {
                "overall_risk_status": org_risk_status,
                "summary_statement": org_risk_summary,
                "monitored_endpoints": posture["total_monitored_endpoints"],
                "threat_resolution_rate": posture["threat_resolution_rate"],
                "automated_containment_rate": posture["automated_containment_rate"],
            },
            "kpis": top_kpis,
            "response_sla": response_metrics,
            "threat_trends": {
                "daily_volume": self.trend_analyzer.get_daily_incident_trends(days=timeframe_days),
                "velocity": trend_velocity,
                "severity_breakdown": severity_dist,
                "status_breakdown": status_dist,
            },
            "endpoint_health": {
                "total": posture["total_monitored_endpoints"],
                "online": posture["online_endpoints"],
                "isolated": posture["isolated_endpoints"],
                "offline": posture["offline_endpoints"],
            },
            "top_risks": risk_endpoints,
            "mitre_attack_summary": mitre_data,
        }

    # -------------------------------------------------------------------------
    # 2. TECHNICAL REPORT PAYLOAD (JSON)
    # -------------------------------------------------------------------------
    def generate_technical_report(self, timeframe_days: int = 30) -> Dict[str, Any]:
        """
        Generates Technical Security Report payload containing:
        - Full Incident List (Alerts & Threats)
        - Event & Action Timeline
        - Indicators of Compromise (IOCs: SHA256 hashes, Remote IPs, Malicious Ports)
        - Response Actions Execution Log
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=timeframe_days)

        # 1. Full Incident List
        alerts = self.db.query(Alert).filter(Alert.created_at >= start_time).order_by(desc(Alert.created_at)).all()
        incidents_list = []
        for a in alerts:
            dev_name = a.device.hostname if (a.device and a.device.hostname) else str(a.device_id)
            rule = a.threat.rule_name if (a.threat and a.threat.rule_name) else "Security Alert"
            incidents_list.append({
                "alert_id": str(a.id),
                "threat_id": str(a.threat_id) if a.threat_id else None,
                "title": a.title,
                "severity": a.severity.value if hasattr(a.severity, 'value') else str(a.severity),
                "status": a.status.value if hasattr(a.status, 'value') else str(a.status),
                "device_name": dev_name,
                "rule_name": rule,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })

        # 2. Timeline
        responses = self.db.query(ResponseAction).filter(ResponseAction.started_at >= start_time).order_by(desc(ResponseAction.started_at)).all()
        timeline_events = []
        for r in responses:
            dev_name = r.device.hostname if (r.device and r.device.hostname) else str(r.device_id)
            act_type = r.action_type.value if hasattr(r.action_type, 'value') else str(r.action_type)
            st = r.status.value if hasattr(r.status, 'value') else str(r.status)
            timeline_events.append({
                "timestamp": r.started_at.isoformat() if r.started_at else None,
                "category": "RESPONSE_ACTION",
                "event_type": act_type,
                "status": st,
                "device": dev_name,
                "detail": f"Response {act_type} initiated by {r.initiated_by} - Status: {st}"
            })

        # 3. Indicators of Compromise (IOCs)
        iocs = []
        threats = self.db.query(Threat).filter(Threat.detected_at >= start_time).all()
        for t in threats:
            if t.scan_result and t.scan_result.sha256:
                iocs.append({
                    "indicator_type": "SHA256_HASH",
                    "value": t.scan_result.sha256,
                    "associated_rule": t.rule_name,
                    "file_name": t.scan_result.file_name,
                })

        net_conns = self.db.query(NetworkConnection).filter(NetworkConnection.created_at >= start_time).all()
        for nc in net_conns:
            if nc.remote_ip:
                iocs.append({
                    "indicator_type": "REMOTE_IP",
                    "value": nc.remote_ip,
                    "associated_rule": f"Port {nc.remote_port} {nc.protocol}",
                    "file_name": nc.process_name or "Network Process",
                })

        # De-duplicate IOCs
        unique_iocs = list({f"{i['indicator_type']}:{i['value']}": i for i in iocs}.values())

        # 4. Response Actions Log
        response_list = []
        for r in responses:
            dev_name = r.device.hostname if (r.device and r.device.hostname) else str(r.device_id)
            act_type = r.action_type.value if hasattr(r.action_type, 'value') else str(r.action_type)
            st = r.status.value if hasattr(r.status, 'value') else str(r.status)
            response_list.append({
                "action_id": str(r.id),
                "action_type": act_type,
                "status": st,
                "device_name": dev_name,
                "initiated_by": r.initiated_by,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "result": r.result
            })

        return {
            "report_type": "TECHNICAL_REPORT",
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "timeframe_days": timeframe_days,
            "total_incidents_count": len(incidents_list),
            "total_iocs_count": len(unique_iocs),
            "total_responses_count": len(response_list),
            "full_incident_list": incidents_list,
            "timeline": timeline_events[:50],
            "indicators": unique_iocs[:50],
            "response_actions": response_list,
        }

    # -------------------------------------------------------------------------
    # 3. PDF REPORT EXPORTER (REPORTLAB)
    # -------------------------------------------------------------------------
    def export_report_pdf(self, report_type: str = "executive", timeframe_days: int = 30) -> bytes:
        """
        Generates a styled multi-page PDF document for Executive or Technical report.
        """
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
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#00f0ff"),
            spaceAfter=6
        )
        h2_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#10b981"),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#222222")
        )
        header_table_style = ParagraphStyle(
            "TableHeader",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#ffffff")
        )

        story = []

        if report_type == "executive":
            data = self.generate_executive_summary_report(timeframe_days=timeframe_days)
            exec_sum = data["executive_summary"]
            kpis = data["kpis"]
            health = data["endpoint_health"]
            risks = data["top_risks"]

            story.append(Paragraph("🛡️ SentinelX EDR — Executive Security Report", title_style))
            story.append(Paragraph(f"<b>Generated:</b> {data['report_generated_at']} | <b>Timeframe:</b> {timeframe_days} Days | <b>Status:</b> <font color='red'><b>{exec_sum['overall_risk_status']}</b></font>", body_style))
            story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#00f0ff"), spaceBefore=6, spaceAfter=10))

            # 1. Executive Summary & KPIs
            story.append(Paragraph("1. Executive Summary & KPIs", h2_style))
            kpi_rows = [
                [Paragraph("<b>Metric</b>", header_table_style), Paragraph("<b>Value</b>", header_table_style)],
                [Paragraph("Total Monitored Endpoints", body_style), Paragraph(str(kpis["total_endpoints"]), body_style)],
                [Paragraph("Online Endpoints", body_style), Paragraph(str(kpis["online_endpoints"]), body_style)],
                [Paragraph("Total Incidents", body_style), Paragraph(str(kpis["total_incidents"]), body_style)],
                [Paragraph("Critical Incidents", body_style), Paragraph(f"<font color='red'><b>{kpis['critical_incidents']}</b></font>", body_style)],
                [Paragraph("Threat Resolution Rate", body_style), Paragraph(f"{exec_sum['threat_resolution_rate']}%", body_style)],
                [Paragraph("Automated Containment Rate", body_style), Paragraph(f"{exec_sum['automated_containment_rate']}%", body_style)],
                [Paragraph("Average Response Time (MTTR)", body_style), Paragraph(f"{kpis['average_response_time_minutes']} min", body_style)],
            ]
            t1 = Table(kpi_rows, colWidths=[270, 270])
            t1.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t1)
            story.append(Spacer(1, 10))

            # 2. Endpoint Health & Top Risks
            story.append(Paragraph("2. Top At-Risk Endpoints", h2_style))
            risk_rows = [
                [Paragraph("<b>Hostname</b>", header_table_style), Paragraph("<b>IP Address</b>", header_table_style), Paragraph("<b>OS</b>", header_table_style), Paragraph("<b>Score</b>", header_table_style), Paragraph("<b>Level</b>", header_table_style)]
            ]
            for r in risks[:7]:
                risk_rows.append([
                    Paragraph(r["hostname"], body_style),
                    Paragraph(r.get("ip_address") or "N/A", body_style),
                    Paragraph(r["os_type"], body_style),
                    Paragraph(str(r["risk_score"]), body_style),
                    Paragraph(f"<font color='red'><b>{r['risk_level']}</b></font>", body_style)
                ])

            t2 = Table(risk_rows, colWidths=[130, 110, 80, 70, 150])
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t2)

        else:
            # Technical Report
            data = self.generate_technical_report(timeframe_days=timeframe_days)
            incidents = data["full_incident_list"]
            iocs = data["indicators"]
            responses = data["response_actions"]

            story.append(Paragraph("⚡ SentinelX EDR — Technical Incident & IOC Report", title_style))
            story.append(Paragraph(f"<b>Generated:</b> {data['report_generated_at']} | <b>Timeframe:</b> {timeframe_days} Days | <b>Total Incidents:</b> {data['total_incidents_count']}", body_style))
            story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#10b981"), spaceBefore=6, spaceAfter=10))

            # 1. Full Incident List
            story.append(Paragraph("1. Incident Detections", h2_style))
            inc_rows = [
                [Paragraph("<b>Title</b>", header_table_style), Paragraph("<b>Severity</b>", header_table_style), Paragraph("<b>Device</b>", header_table_style), Paragraph("<b>Status</b>", header_table_style)]
            ]
            for inc in incidents[:10]:
                inc_rows.append([
                    Paragraph(inc["title"][:40], body_style),
                    Paragraph(inc["severity"], body_style),
                    Paragraph(inc["device_name"], body_style),
                    Paragraph(inc["status"], body_style),
                ])
            t_inc = Table(inc_rows, colWidths=[200, 100, 140, 100])
            t_inc.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t_inc)
            story.append(Spacer(1, 10))

            # 2. Indicators of Compromise (IOCs)
            story.append(Paragraph("2. Indicators of Compromise (IOCs)", h2_style))
            ioc_rows = [
                [Paragraph("<b>Type</b>", header_table_style), Paragraph("<b>Value / Hash</b>", header_table_style), Paragraph("<b>Associated Rule</b>", header_table_style)]
            ]
            for ioc in iocs[:10]:
                ioc_rows.append([
                    Paragraph(ioc["indicator_type"], body_style),
                    Paragraph(ioc["value"][:45], body_style),
                    Paragraph(ioc["associated_rule"][:40], body_style),
                ])
            t_ioc = Table(ioc_rows, colWidths=[120, 240, 180])
            t_ioc.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(t_ioc)

        doc.build(story)
        return buffer.getvalue()

    # -------------------------------------------------------------------------
    # 4. CSV REPORT EXPORTER
    # -------------------------------------------------------------------------
    def export_dataset_to_csv(self, dataset_type: str, timeframe_days: int = 30) -> str:
        """
        Exports analytics datasets (incidents, endpoints, mitre, technical_iocs, technical_responses) to CSV format.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        if dataset_type == "incidents":
            writer.writerow(["Date", "Total Alerts", "Critical", "High", "Medium", "Low"])
            trends = self.trend_analyzer.get_daily_incident_trends(days=timeframe_days)
            for row in trends:
                writer.writerow([row["date"], row["total"], row["critical"], row["high"], row["medium"], row["low"]])

        elif dataset_type == "endpoints":
            writer.writerow(["Device ID", "Hostname", "IP Address", "Status", "OS", "Risk Score", "Risk Level", "Active Alerts", "Unresolved Threats"])
            endpoints = self.metrics_calc.calculate_endpoint_risk_scores(timeframe_days)
            for ep in endpoints:
                writer.writerow([
                    ep["device_id"], ep["hostname"], ep["ip_address"], ep["status"], ep["os_type"],
                    ep["risk_score"], ep["risk_level"], ep["active_alerts_count"], ep["unresolved_threats"]
                ])

        elif dataset_type == "mitre":
            writer.writerow(["Technique ID", "Technique Name", "Tactic ID", "Tactic Name", "Count", "Percentage"])
            mitre_data = self.mitre_mapper.analyze_mitre_attack_coverage(timeframe_days, limit_techniques=50)
            for tech in mitre_data.get("top_techniques", []):
                writer.writerow([
                    tech["technique_id"], tech["technique_name"], tech["tactic_id"], tech["tactic_name"],
                    tech["count"], f"{tech['percentage']}%"
                ])

        elif dataset_type == "technical_iocs":
            writer.writerow(["Indicator Type", "Value", "Associated Rule", "Process / File Name"])
            tech_data = self.generate_technical_report(timeframe_days=timeframe_days)
            for ioc in tech_data.get("indicators", []):
                writer.writerow([ioc["indicator_type"], ioc["value"], ioc["associated_rule"], ioc["file_name"]])

        elif dataset_type == "technical_responses":
            writer.writerow(["Action ID", "Action Type", "Status", "Device Name", "Initiated By", "Started At", "Completed At"])
            tech_data = self.generate_technical_report(timeframe_days=timeframe_days)
            for resp in tech_data.get("response_actions", []):
                writer.writerow([resp["action_id"], resp["action_type"], resp["status"], resp["device_name"], resp["initiated_by"], resp["started_at"], resp["completed_at"]])

        else:
            raise ValueError(f"Unknown dataset_type: {dataset_type}")

        return output.getvalue()
