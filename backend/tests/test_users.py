import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import SessionLocal
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

def get_user_headers(username, password):
    res = client.post(
        "/api/v1/auth/login/json",
        json={"username_or_email": username, "password": password}
    )
    assert res.status_code == 200, f"User login failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_admin_user_crud_operations():
    admin_headers = get_admin_headers()
    random_str = str(uuid.uuid4())[:8]
    email = f"user_crud_{random_str}@sentinelx.io"
    username = f"user_crud_{random_str}"
    password = "SecurePassword123!"

    # 1. Create User as Admin
    create_res = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": email,
            "username": username,
            "password": password,
            "role": "ANALYST"
        }
    )
    assert create_res.status_code == 201
    user_data = create_res.json()
    user_id = user_data["id"]
    assert user_data["role"] == "ANALYST"

    # 2. List Users as Admin
    list_res = client.get("/api/v1/users", headers=admin_headers)
    assert list_res.status_code == 200
    users_list = list_res.json()
    assert any(u["id"] == user_id for u in users_list)

    # 3. Get Specific User as Admin
    get_res = client.get(f"/api/v1/users/{user_id}", headers=admin_headers)
    assert get_res.status_code == 200
    assert get_res.json()["email"] == email

    # 4. Update User Role & Status as Admin
    update_res = client.patch(
        f"/api/v1/users/{user_id}",
        headers=admin_headers,
        json={"role": "VIEWER", "is_active": True}
    )
    assert update_res.status_code == 200
    assert update_res.json()["role"] == "VIEWER"

    # 5. Non-Admin (Viewer) cannot list users or create users
    viewer_headers = get_user_headers(username, password)
    forbidden_list = client.get("/api/v1/users", headers=viewer_headers)
    assert forbidden_list.status_code == 403

    forbidden_create = client.post(
        "/api/v1/users",
        headers=viewer_headers,
        json={"email": "bad@sentinelx.io", "username": "baduser", "password": "Password123!", "role": "ANALYST"}
    )
    assert forbidden_create.status_code == 403

    # 6. Delete User as Admin
    delete_res = client.delete(f"/api/v1/users/{user_id}", headers=admin_headers)
    assert delete_res.status_code == 204

    # Verify deleted
    get_deleted = client.get(f"/api/v1/users/{user_id}", headers=admin_headers)
    assert get_deleted.status_code == 404
