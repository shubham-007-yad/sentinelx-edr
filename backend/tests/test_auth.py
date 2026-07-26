import uuid
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_and_health():
    """Verify application root and health check endpoints."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert "version" in res_root.json()

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

# ===================================================================
# Phase 8: Comprehensive Verification Test Suite
# ===================================================================

def test_user_registration():
    """1. Test User registration."""
    random_str = str(uuid.uuid4())[:8]
    email = f"reg_{random_str}@sentinelx.io"
    username = f"user_reg_{random_str}"
    password = "SecurePassword123!"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
            "role": "ANALYST"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == email
    assert data["username"] == username
    assert data["role"] == "ANALYST"
    assert "id" in data
    assert "password_hash" not in data  # Ensure hash is omitted

def test_duplicate_email_handling():
    """2. Test Duplicate email handling."""
    random_str = str(uuid.uuid4())[:8]
    email = f"dup_{random_str}@sentinelx.io"
    password = "SecurePassword123!"

    # First registration (Succeeds)
    res1 = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "username": f"user1_{random_str}",
            "password": password,
            "role": "ANALYST"
        }
    )
    assert res1.status_code == 201

    # Second registration with SAME email (Fails with 400 Bad Request)
    res2 = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "username": f"user2_{random_str}",
            "password": password,
            "role": "ANALYST"
        }
    )
    assert res2.status_code == 400
    assert "email already exists" in res2.json()["detail"].lower()

def test_login_with_correct_password():
    """3. Test Login with correct password."""
    random_str = str(uuid.uuid4())[:8]
    email = f"login_good_{random_str}@sentinelx.io"
    username = f"user_good_{random_str}"
    password = "SecurePassword123!"

    # Register
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "username": username, "password": password, "role": "ANALYST"}
    )

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
    """4. Test Login with incorrect password."""
    random_str = str(uuid.uuid4())[:8]
    email = f"login_bad_{random_str}@sentinelx.io"
    username = f"user_bad_{random_str}"
    correct_password = "SecurePassword123!"
    wrong_password = "WrongPassword999!"

    # Register
    client.post(
        "/api/v1/auth/register",
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
    """5. Test Accessing /me with a valid token."""
    random_str = str(uuid.uuid4())[:8]
    email = f"me_valid_{random_str}@sentinelx.io"
    username = f"user_me_{random_str}"
    password = "SecurePassword123!"

    # Register & Login
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "username": username, "password": password, "role": "ADMIN"}
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
    assert me_data["role"] == "ADMIN"

def test_access_me_without_token():
    """6. Test Accessing /me without a token (or with an invalid token)."""
    # 1. Without Authorization Header (Fails with 401)
    res_no_header = client.get("/api/v1/auth/me")
    assert res_no_header.status_code == 401

    # 2. With Invalid Token String (Fails with 401)
    res_invalid_token = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid_jwt_token_string"}
    )
    assert res_invalid_token.status_code == 401
