"""
Unit Tests for Phase 2 - Executive Analytics API Endpoints
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.db.init_db import init_db

client = TestClient(app)


def get_admin_headers():
    db = SessionLocal()
    init_db(db)
    db.close()
    res = client.post(
        "/api/v1/auth/login/json",
        json={"username_or_email": "admin", "password": "AdminPassword123!"}
    )
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_analytics_api_endpoints():
    Base.metadata.create_all(bind=engine)
    headers = get_admin_headers()

    # 1. GET /api/v1/analytics/top-metrics
    res_top = client.get("/api/v1/analytics/top-metrics", headers=headers)
    assert res_top.status_code == 200
    top_data = res_top.json()
    assert "total_endpoints" in top_data
    assert "online_endpoints" in top_data
    assert "total_incidents" in top_data
    assert "critical_incidents" in top_data
    assert "threats_today" in top_data
    assert "alerts_today" in top_data
    assert "responses_executed" in top_data
    assert "average_response_time_minutes" in top_data

    # 2. GET /api/v1/analytics/dashboard
    res_dash = client.get("/api/v1/analytics/dashboard?timeframe_days=7", headers=headers)
    assert res_dash.status_code == 200
    dash_data = res_dash.json()
    assert "top_metrics" in dash_data
    assert "posture" in dash_data
    assert "alerts_by_severity" in dash_data
    assert "incident_velocity" in dash_data
    assert "top_risk_endpoints" in dash_data
    assert "mitre_summary" in dash_data

    # 3. GET /api/v1/analytics/endpoint-risk
    res_risk = client.get("/api/v1/analytics/endpoint-risk?timeframe_days=30&limit=5", headers=headers)
    assert res_risk.status_code == 200
    risk_data = res_risk.json()
    assert isinstance(risk_data, list)

    # 4. GET /api/v1/analytics/mitre-attack
    res_mitre = client.get("/api/v1/analytics/mitre-attack?timeframe_days=30", headers=headers)
    assert res_mitre.status_code == 200
    mitre_data = res_mitre.json()
    assert "tactics_breakdown" in mitre_data
    assert "top_techniques" in mitre_data

    # 4b. GET /api/v1/analytics/mitre-matrix
    res_matrix = client.get("/api/v1/analytics/mitre-matrix?timeframe_days=30", headers=headers)
    assert res_matrix.status_code == 200
    matrix_data = res_matrix.json()
    assert "tactic_coverage_percent" in matrix_data
    assert "technique_coverage_percent" in matrix_data
    assert "top_tactics" in matrix_data
    assert "technique_frequency" in matrix_data
    assert "matrix_columns" in matrix_data
    assert len(matrix_data["matrix_columns"]) == 12

    # 5. GET /api/v1/analytics/incident-trends
    res_trends = client.get("/api/v1/analytics/incident-trends?days=7", headers=headers)
    assert res_trends.status_code == 200
    trends_data = res_trends.json()
    assert "daily_trends" in trends_data
    assert len(trends_data["daily_trends"]) == 7

    # 5b. GET /api/v1/analytics/trends/charts (24h, 7d, 30d, custom)
    for tf in ["24h", "7d", "30d"]:
        res_chart = client.get(f"/api/v1/analytics/trends/charts?timeframe={tf}", headers=headers)
        assert res_chart.status_code == 200
        chart_data = res_chart.json()
        assert "series" in chart_data
        assert "threats_per_day" in chart_data["series"]
        assert "alerts_per_day" in chart_data["series"]
        assert "endpoint_activity" in chart_data["series"]
        assert "usb_insertions" in chart_data["series"]
        assert "network_detections" in chart_data["series"]
        assert "process_detections" in chart_data["series"]

    # Test Custom Range
    res_custom = client.get(
        "/api/v1/analytics/trends/charts?timeframe=custom&start_date=2026-08-01T00:00:00Z&end_date=2026-08-05T23:59:59Z",
        headers=headers
    )
    assert res_custom.status_code == 200
    assert len(res_custom.json()["series"]["threats_per_day"]) > 0

    # 6. GET /api/v1/analytics/response-performance
    res_resp = client.get("/api/v1/analytics/response-performance?timeframe_days=30", headers=headers)
    assert res_resp.status_code == 200
    resp_data = res_resp.json()
    assert "mtta_minutes" in resp_data
    assert "mttr_minutes" in resp_data

    # 7. GET /api/v1/analytics/report (Executive Report JSON)
    res_report = client.get("/api/v1/analytics/report?timeframe_days=7", headers=headers)
    assert res_report.status_code == 200
    report_data = res_report.json()
    assert "executive_summary" in report_data
    assert "kpis" in report_data

    # 7b. GET /api/v1/analytics/report/technical (Technical Report JSON)
    res_tech = client.get("/api/v1/analytics/report/technical?timeframe_days=30", headers=headers)
    assert res_tech.status_code == 200
    tech_data = res_tech.json()
    assert "full_incident_list" in tech_data
    assert "timeline" in tech_data
    assert "indicators" in tech_data
    assert "response_actions" in tech_data

    # 7c. GET /api/v1/analytics/report/pdf (PDF Export - Executive & Technical)
    for r_type in ["executive", "technical"]:
        res_pdf = client.get(f"/api/v1/analytics/report/pdf?report_type={r_type}&timeframe_days=30", headers=headers)
        assert res_pdf.status_code == 200
        assert "application/pdf" in res_pdf.headers["content-type"]
        assert len(res_pdf.content) > 100

    # 8. GET /api/v1/analytics/export-csv
    for ds in ["incidents", "endpoints", "mitre", "technical_iocs", "technical_responses"]:
        res_csv = client.get(f"/api/v1/analytics/export-csv?dataset_type={ds}", headers=headers)
        assert res_csv.status_code == 200
        assert "text/csv" in res_csv.headers["content-type"]
        assert len(res_csv.text) > 0
