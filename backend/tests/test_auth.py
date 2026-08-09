import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import SessionLocal
from app.db.init_db import init_db

client = TestClient(app)

def get_admin_headers():
    """Helper to ensure seed Admin user exists, login, and return authorization header."""
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

def test_root_and_health():
    """Verify application root and health check endpoints."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "version" in res_root.json()

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "UP"

def test_public_registration_disabled():
    """Verify that public self-registration is disabled (HTTP 403 Forbidden)."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "hacker@evil.com",
            "username": "hacker",
            "password": "HackerPassword123!",
            "role": "ADMIN"
        }
    )
    assert response.status_code == 403
    assert "public registration is disabled" in response.json()["detail"].lower()

def test_login_with_correct_password():
    """Test Login with correct password for Admin-created user."""
    headers = get_admin_headers()
    random_str = str(uuid.uuid4())[:8]
    email = f"login_good_{random_str}@sentinelx.io"
    username = f"user_good_{random_str}"
    password = "SecurePassword123!"

    # Admin creates user via POST /users
    create_res = client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": email, "username": username, "password": password, "role": "ANALYST"}
    )
    assert create_res.status_code == 201

    # Login via JSON
    res_json = client.post(
        "/api/v1/auth/login/json",
        json={"username_or_email": email, "password": password}
    )
    assert res_json.status_code == 200
    data_json = res_json.json()
    assert "access_token" in data_json
    assert data_json["token_type"] == "bearer"
    assert data_json["user"]["email"] == email

    # Login via Form Data
    res_form = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password}
    )
    assert res_form.status_code == 200
    assert "access_token" in res_form.json()

def test_login_with_incorrect_password():
    """Test Login with incorrect password."""
    headers = get_admin_headers()
    random_str = str(uuid.uuid4())[:8]
    email = f"login_bad_{random_str}@sentinelx.io"
    username = f"user_bad_{random_str}"
    correct_password = "SecurePassword123!"
    wrong_password = "WrongPassword999!"

    # Admin creates user
    client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": email, "username": username, "password": correct_password, "role": "ANALYST"}
    )

    # Login with wrong password (Fails with 401 Unauthorized)
    response = client.post(
        "/api/v1/auth/login/json",
        json={"username_or_email": username, "password": wrong_password}
    )
    assert response.status_code == 401
    assert "incorrect username/email or password" in response.json()["detail"].lower()

def test_access_me_with_valid_token():
    """Test Accessing /me with a valid token."""
    headers = get_admin_headers()
    random_str = str(uuid.uuid4())[:8]
    email = f"me_valid_{random_str}@sentinelx.io"
    username = f"user_me_{random_str}"
    password = "SecurePassword123!"

    # Admin creates new user
    client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": email, "username": username, "password": password, "role": "ANALYST"}
    )
    
    login_res = client.post(
        "/api/v1/auth/login/json",
        json={"username_or_email": email, "password": password}
    )
    token = login_res.json()["access_token"]

    # Request /me with Bearer token
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    me_data = response.json()
    assert me_data["username"] == username
    assert me_data["email"] == email
    assert me_data["role"] == "ANALYST"

def test_access_me_without_token():
    """Test Accessing /me without a token."""
    res_no_header = client.get("/api/v1/auth/me")
    assert res_no_header.status_code == 401

    res_invalid_token = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid_jwt_token_string"}
    )
    assert res_invalid_token.status_code == 401
