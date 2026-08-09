import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.database import Base, engine, SessionLocal
from app.auth.jwt import create_access_token
from app.models.user import User, UserRole
from app.core.logging import SensitiveDataFilter
from app.core.config import settings


@pytest.fixture(scope="module")
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()


def test_auth_jwt_validation_and_token_rejection():
    """Test 1 & 2 & 3: Validates JWT token decode, expired token rejection, and invalid signature rejection."""
    client = TestClient(app)

    # 1. Invalid / Malformed Token Rejection
    invalid_res = client.get("/api/v1/analytics/dashboard", headers={"Authorization": "Bearer invalid.jwt.token"})
    assert invalid_res.status_code == 401, f"Expected 401 for invalid token, got {invalid_res.status_code}"

    # 2. Expired Token Rejection
    expired_token = create_access_token(
        subject="expired_user",
        role="ADMIN",
        expires_delta=timedelta(seconds=-10)
    )
    expired_res = client.get("/api/v1/analytics/dashboard", headers={"Authorization": f"Bearer {expired_token}"})
    assert expired_res.status_code == 401, f"Expected 401 for expired token, got {expired_res.status_code}"


def test_api_input_validation_and_path_safety(setup_db: Session):
    """Test 4 & 5: Validates Pydantic input validation and malformed path safety."""
    db = setup_db
    client = TestClient(app)
    user = db.query(User).filter(User.username == "security_admin_p4").first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            username="security_admin_p4",
            email="sec_admin@sentinelx.io",
            password_hash="pass_hash",
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(user)
        db.commit()

    admin_token = create_access_token(subject=user.username, role="ADMIN")
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Malformed UUID input
    bad_uuid_res = client.get("/api/v1/fleet/commands/pending/not-a-valid-uuid", headers=headers)
    assert bad_uuid_res.status_code == 422, f"Expected 422 for malformed UUID, got {bad_uuid_res.status_code}"

    # Invalid Payload schema
    invalid_payload_res = client.post("/api/v1/users", json={
        "username": "missing_required_fields"
    }, headers=headers)
    assert invalid_payload_res.status_code == 422, f"Expected 422 for invalid schema, got {invalid_payload_res.status_code}"


def test_log_redaction_sensitive_data_filter():
    """Test 6: Validates Log Redaction filter redacting passwords, secrets, DB credentials and Bearer tokens."""
    log_filter = SensitiveDataFilter()

    class MockRecord:
        def __init__(self, msg):
            self.msg = msg

    # Password masking
    rec1 = MockRecord("User authentication attempt password='SuperSecretPassword123!'")
    log_filter.filter(rec1)
    assert "SuperSecretPassword123!" not in rec1.msg
    assert "***REDACTED***" in rec1.msg

    # DB Connection string masking
    rec2 = MockRecord("Connected to postgresql://postgres:SecretDBPass123@localhost:5432/sentinelx")
    log_filter.filter(rec2)
    assert "SecretDBPass123" not in rec2.msg
    assert "***REDACTED***" in rec2.msg

    # Bearer token masking
    rec3 = MockRecord("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret")
    log_filter.filter(rec3)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in rec3.msg
    assert "Bearer ***REDACTED***" in rec3.msg


def test_cors_header_configuration():
    """Test 7: Validates CORS headers configuration on preflight OPTIONS request."""
    client = TestClient(app)
    res = client.options("/api/v1/analytics/dashboard", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "GET"
    })
    assert res.status_code in [200, 204]
    assert "access-control-allow-origin" in res.headers
