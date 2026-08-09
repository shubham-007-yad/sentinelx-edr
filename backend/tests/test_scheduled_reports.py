"""
Unit Tests for Phase 7 - Scheduled Reports Configuration & Execution
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


def test_scheduled_reports_crud_and_execution():
    Base.metadata.create_all(bind=engine)
    headers = get_admin_headers()

    # 1. Create Scheduled Reports (Daily SOC Summary, Weekly Executive Report, Monthly Compliance Report)
    report1_data = {
        "title": "Daily SOC Summary",
        "report_type": "TECHNICAL",
        "frequency": "DAILY",
        "timeframe_days": 1,
        "export_format": "JSON",
        "recipients": ["soc@sentinelx.io", "tier1@sentinelx.io"],
        "is_enabled": True
    }
    res_create1 = client.post("/api/v1/scheduled-reports", headers=headers, json=report1_data)
    assert res_create1.status_code == 201
    cfg1 = res_create1.json()
    assert cfg1["title"] == "Daily SOC Summary"
    assert cfg1["frequency"] == "DAILY"
    assert cfg1["next_run_at"] is not None

    report2_data = {
        "title": "Weekly Executive Report",
        "report_type": "EXECUTIVE",
        "frequency": "WEEKLY",
        "timeframe_days": 7,
        "export_format": "PDF",
        "recipients": ["ciso@sentinelx.io", "vp-security@sentinelx.io"],
        "is_enabled": True
    }
    res_create2 = client.post("/api/v1/scheduled-reports", headers=headers, json=report2_data)
    assert res_create2.status_code == 201
    cfg2 = res_create2.json()
    cfg2_id = cfg2["id"]

    report3_data = {
        "title": "Monthly Compliance Report",
        "report_type": "EXECUTIVE",
        "frequency": "MONTHLY",
        "timeframe_days": 30,
        "export_format": "CSV",
        "recipients": ["compliance@sentinelx.io"],
        "is_enabled": True
    }
    res_create3 = client.post("/api/v1/scheduled-reports", headers=headers, json=report3_data)
    assert res_create3.status_code == 201

    # 2. List Scheduled Reports
    res_list = client.get("/api/v1/scheduled-reports", headers=headers)
    assert res_list.status_code == 200
    configs = res_list.json()
    assert len(configs) >= 3

    # 3. Get Single Config
    res_get = client.get(f"/api/v1/scheduled-reports/{cfg2_id}", headers=headers)
    assert res_get.status_code == 200
    assert res_get.json()["title"] == "Weekly Executive Report"

    # 4. Update Config
    res_update = client.patch(
        f"/api/v1/scheduled-reports/{cfg2_id}",
        headers=headers,
        json={"title": "Weekly Executive Board Summary", "timeframe_days": 14}
    )
    assert res_update.status_code == 200
    assert res_update.json()["title"] == "Weekly Executive Board Summary"
    assert res_update.json()["timeframe_days"] == 14

    # 5. Trigger Immediate Execution (Run Now)
    res_run = client.post(f"/api/v1/scheduled-reports/{cfg2_id}/run-now", headers=headers)
    assert res_run.status_code == 200
    run_output = res_run.json()
    assert run_output["config_id"] == cfg2_id
    assert run_output["executed_at"] is not None
    assert run_output["next_run_at"] is not None

    # 6. Delete Config
    res_del = client.delete(f"/api/v1/scheduled-reports/{cfg2_id}", headers=headers)
    assert res_del.status_code == 204

    # Verify deleted
    res_del_check = client.get(f"/api/v1/scheduled-reports/{cfg2_id}", headers=headers)
    assert res_del_check.status_code == 404
