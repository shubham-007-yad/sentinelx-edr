from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_liveness_health_endpoint():
    """
    Tests GET /health liveness probe.
    Expects HTTP 200 OK with status="UP".
    """
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UP"
    assert "service" in data
    assert "version" in data
    assert "timestamp" in data


def test_readiness_endpoint():
    """
    Tests GET /ready readiness probe across FastAPI, PostgreSQL, Redis, and WebSockets.
    """
    response = client.get("/ready")
    assert response.status_code in (200, 503)
    data = response.json()
    if response.status_code == 200:
        assert data["status"] == "UP"
        assert "dependencies" in data
        deps = data["dependencies"]
        assert "fastapi" in deps
        assert "postgres" in deps
        assert "redis" in deps
        assert "websocket" in deps
        assert deps["postgres"]["status"] == "UP"
    else:
        # If DB or Redis is unavailable during local standalone test run
        assert data["detail"]["status"] == "DOWN"
