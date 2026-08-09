"""
Executive Reporting & Security Analytics API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Response
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user
from app.models.user import User
from app.analytics.engine import AnalyticsEngine
from app.schemas.analytics import (
    ExecutiveTopMetricsOut,
    ExecutiveDashboardSummaryOut,
    EndpointRiskScoreOut,
    MitreAttackAnalyticsOut,
    IncidentTrendsOut,
    ResponsePerformanceOut,
)

router = APIRouter(prefix="/analytics", tags=["Executive Analytics & Reporting"])


@router.get(
    "/dashboard",
    response_model=ExecutiveDashboardSummaryOut,
    summary="Get full Executive Dashboard summary",
    description="Returns high-level decision support metrics, risk scores, posture, trends, and MITRE mapping."
)
def get_executive_dashboard(
    timeframe_days: int = Query(7, ge=1, le=365, description="Timeframe in days for historical analysis"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_executive_dashboard_summary(timeframe_days=timeframe_days)


@router.get(
    "/top-metrics",
    response_model=ExecutiveTopMetricsOut,
    summary="Get top executive KPI cards",
    description="Returns top executive metrics: total/online endpoints, total/critical incidents, threats/alerts today, responses executed, and average response time."
)
def get_top_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_top_metrics()


@router.get(
    "/endpoint-risk",
    response_model=List[EndpointRiskScoreOut],
    summary="Get endpoint risk rankings",
    description="Returns devices ordered by dynamic risk score (0 to 100)."
)
def get_endpoint_risk(
    timeframe_days: int = Query(30, ge=1, le=365),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_endpoint_risk_analytics(timeframe_days=timeframe_days, limit=limit)


@router.get(
    "/mitre-attack",
    response_model=MitreAttackAnalyticsOut,
    summary="Get MITRE ATT&CK matrix analytics",
    description="Returns observed threat counts mapped to MITRE ATT&CK Tactics and Techniques."
)
def get_mitre_attack(
    timeframe_days: int = Query(30, ge=1, le=365),
    limit_techniques: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_mitre_attack_analytics(timeframe_days=timeframe_days, limit_techniques=limit_techniques)


@router.get(
    "/mitre-matrix",
    summary="Get full MITRE ATT&CK Matrix Heatmap & Coverage",
    description="Returns 12-tactic MITRE ATT&CK Matrix Heatmap columns, cell heat levels, technique frequencies, and coverage percentages."
)
def get_mitre_matrix(
    timeframe_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_mitre_matrix_heatmap(timeframe_days=timeframe_days)


@router.get(
    "/incident-trends",
    response_model=IncidentTrendsOut,
    summary="Get daily incident trends and velocity",
    description="Returns daily incident time-series counts by severity and directional velocity indicator."
)
def get_incident_trends(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_incident_trends(days=days)


from datetime import datetime


@router.get(
    "/trends/charts",
    summary="Get multi-stream trend charts data",
    description="Returns time-series trend chart data for Threats, Alerts, Endpoint activity, USB insertions, Network detections, and Process detections across 24h, 7d, 30d, or custom date ranges."
)
def get_trend_charts(
    timeframe: str = Query("7d", pattern="^(24h|7d|30d|custom)$", description="Timeframe window (24h, 7d, 30d, custom)"),
    start_date: Optional[datetime] = Query(None, description="ISO Start Date for custom timeframe"),
    end_date: Optional[datetime] = Query(None, description="ISO End Date for custom timeframe"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_multi_stream_trends(
        timeframe=timeframe,
        start_date=start_date,
        end_date=end_date
    )


@router.get(
    "/response-performance",
    response_model=ResponsePerformanceOut,
    summary="Get MTTA, MTTR, and SLA response metrics",
    description="Returns Mean Time to Acknowledge (MTTA), Mean Time to Respond (MTTR), and SLA compliance rates."
)
def get_response_performance(
    timeframe_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.get_response_performance(timeframe_days=timeframe_days)


@router.get(
    "/report",
    summary="Generate executive summary report payload (JSON)",
    description="Generates a complete executive report package for CISO / Management review."
)
def get_executive_report(
    timeframe_days: int = Query(7, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.generate_executive_report(timeframe_days=timeframe_days)


@router.get(
    "/report/technical",
    summary="Generate technical incident report payload (JSON)",
    description="Generates detailed technical report package containing incident list, event timelines, IOC indicators, and response logs."
)
def get_technical_report(
    timeframe_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    return engine.generate_technical_report(timeframe_days=timeframe_days)


@router.get(
    "/report/pdf",
    summary="Export PDF Report Document",
    description="Generates and streams a styled multi-page PDF document for Executive or Technical security reports."
)
def get_report_pdf(
    report_type: str = Query("executive", pattern="^(executive|technical)$", description="Type of report: executive or technical"),
    timeframe_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    pdf_bytes = engine.export_report_pdf(report_type=report_type, timeframe_days=timeframe_days)
    filename = f"sentinelx_{report_type}_report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get(
    "/export-csv",
    summary="Export analytics dataset to CSV",
    description="Returns CSV formatted data stream for dataset types: incidents, endpoints, mitre, technical_iocs, or technical_responses."
)
def export_analytics_csv(
    dataset_type: str = Query("incidents", pattern="^(incidents|endpoints|mitre|technical_iocs|technical_responses)$"),
    timeframe_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    engine = AnalyticsEngine(db)
    csv_content = engine.export_analytics_csv(dataset_type=dataset_type, timeframe_days=timeframe_days)
    filename = f"sentinelx_{dataset_type}_report.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
