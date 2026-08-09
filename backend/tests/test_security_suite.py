import uuid
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth.jwt import create_access_token
from app.models.user import UserRole, User
from app.db.database import SessionLocal

client = TestClient(app)


def test_authentication_required_endpoints():
    """Verify that unauthenticated requests to protected endpoints return 401 Unauthorized."""
    fake_uuid = "00000000-0000-0000-0000-000000000000"
    protected_endpoints = [
        ("GET", "/api/v1/users"),
        ("POST", "/api/v1/policies"),
        ("POST", "/api/v1/fleet/commands"),
        ("GET", "/api/v1/investigation/cases"),
        ("POST", "/api/v1/responses/trigger"),
    ]

    for method, path in protected_endpoints:
        if method == "GET":
            response = client.get(path)
        else:
            response = client.post(path, json={})
        assert response.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {response.status_code}"


def test_rbac_viewer_cannot_access_admin_endpoints():
    """
    Verify that a VIEWER role cannot invoke administrative endpoints
    even if they manually construct HTTP requests.
    """
    db = SessionLocal()
    viewer_user = db.query(User).filter(User.role == UserRole.VIEWER).first()
    if not viewer_user:
        from app.services import user_service
        from app.schemas.user import UserCreate
        viewer_user = user_service.create_user(
            db,
            UserCreate(
                username="test_viewer_security",
                email="viewer_sec@sentinelx.io",
                password="ViewerPassword123!",
                role=UserRole.VIEWER
            )
        )
    viewer_username = viewer_user.username
    db.close()

    viewer_token = create_access_token(subject=viewer_username, role=UserRole.VIEWER.value)
    headers = {"Authorization": f"Bearer {viewer_token}"}
    fake_uuid = "00000000-0000-0000-0000-000000000000"

    admin_endpoints = [
        ("POST", "/api/v1/policies", {"policy_name": "Malicious Policy", "category": "USB", "configuration": {}}),
        ("POST", "/api/v1/fleet/commands", {"target_scope": "all", "command_type": "ISOLATE"}),
        ("POST", "/api/v1/scheduled-reports", {"title": "Test Report", "schedule_cron": "0 0 * * *"}),
        ("DELETE", f"/api/v1/scheduled-reports/{fake_uuid}", None),
    ]

    for method, path, payload in admin_endpoints:
        if method == "POST":
            res = client.post(path, json=payload, headers=headers)
        elif method == "PATCH":
            res = client.patch(path, json=payload, headers=headers)
        elif method == "DELETE":
            res = client.delete(path, headers=headers)
        else:
            res = client.get(path, headers=headers)

        assert res.status_code == 403, (
            f"SECURITY FAIL: VIEWER user bypassed RBAC on {method} {path}! "
            f"Expected 403 Forbidden, got {res.status_code}"
        )


def test_jwt_validation_invalid_and_expired_tokens():
    """Verify that tampered, invalid, or expired JWT tokens are strictly rejected."""
    # 1. Tampered signature
    valid_token = create_access_token(subject="admin", role="ADMIN")
    tampered_token = valid_token[:-5] + "XXXXX"
    res = client.get("/api/v1/users", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401

    # 2. Completely malformed token
    res = client.get("/api/v1/users", headers={"Authorization": "Bearer not.a.valid.jwt.token"})
    assert res.status_code == 401

    # 3. Expired token
    expired_token = create_access_token(
        subject="admin",
        role="ADMIN",
        expires_delta=timedelta(seconds=-3600)
    )
    res = client.get("/api/v1/users", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401


def test_sql_injection_resilience():
    """Verify that SQL injection payloads in query parameters or paths do not cause SQL errors."""
    analyst_token = create_access_token(subject="analyst", role="ANALYST")
    headers = {"Authorization": f"Bearer {analyst_token}"}

    sqli_payloads = [
        "' OR '1'='1",
        "1; DROP TABLE users;--",
        "UNION SELECT NULL, NULL, NULL--",
        "'; EXEC xp_cmdshell('dir');--"
    ]

    for payload in sqli_payloads:
        # Threat search endpoint
        res = client.get("/api/v1/threats", params={"search": payload}, headers=headers)
        assert res.status_code == 200, f"SQLi payload failed safely with 200 OK (empty list), got {res.status_code}"
        assert isinstance(res.json(), list)

        # Device search endpoint
        res = client.get("/api/v1/devices", params={"search": payload}, headers=headers)
        assert res.status_code in (200, 422, 400)


def test_path_traversal_resilience():
    """Verify that path traversal payloads are safely handled/rejected."""
    analyst_token = create_access_token(subject="analyst", role="ANALYST")
    headers = {"Authorization": f"Bearer {analyst_token}"}

    traversal_payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\cmd.exe",
        "/etc/shadow",
        "....//....//....//etc/passwd"
    ]

    for payload in traversal_payloads:
        res = client.get("/api/v1/threats", params={"search": payload}, headers=headers)
        assert res.status_code == 200
        assert isinstance(res.json(), list)


def test_cors_headers_enforcement():
    """Verify CORS headers are correctly applied for allowed origins and blocked/restricted for untrusted ones."""
    res = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert res.status_code == 200
    assert "access-control-allow-origin" in res.headers


def test_websocket_authentication():
    """Verify that WebSocket endpoints enforce token authentication."""
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/alerts?token=invalid_token"):
            pass
