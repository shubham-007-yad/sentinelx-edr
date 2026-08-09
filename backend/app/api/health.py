import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings
from app.core.websocket_manager import websocket_manager
import redis

router = APIRouter(tags=["System Health & Readiness"])


@router.get("/health", status_code=status.HTTP_200_OK, summary="Liveness Health Check")
def health_check():
    """
    Liveness Check:
    Verifies that the FastAPI application process is running and accepting HTTP requests.
    Used by load balancers, Nginx reverse proxy, Docker container healthchecks, and Kubernetes probes.
    """
    return {
        "status": "UP",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/ready", summary="Readiness Check for External Dependencies")
def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness Check:
    Verifies that the service can communicate with all critical downstream dependencies:
    - FastAPI (Self)
    - PostgreSQL Database (executes SELECT 1)
    - Redis Task Queue (executes ping())
    - WebSocket Manager (inspects active connection count)
    Returns HTTP 200 OK if all dependencies are UP, or HTTP 503 Service Unavailable if any fail.
    """
    dependencies = {}
    is_ready = True

    # 1. FastAPI status
    dependencies["fastapi"] = {
        "status": "UP",
        "version": settings.VERSION
    }

    # 2. PostgreSQL DB Check
    t0 = time.time()
    try:
        db.execute(text("SELECT 1;"))
        db_latency = round((time.time() - t0) * 1000, 2)
        dependencies["postgres"] = {
            "status": "UP",
            "latency_ms": db_latency
        }
    except Exception as e:
        is_ready = False
        dependencies["postgres"] = {
            "status": "DOWN",
            "error": str(e)
        }

    # 3. Redis Task Queue Check
    t0 = time.time()
    try:
        r = redis.Redis.from_url(settings.REDIS_URL, socket_timeout=2.0)
        r.ping()
        redis_latency = round((time.time() - t0) * 1000, 2)
        dependencies["redis"] = {
            "status": "UP",
            "latency_ms": redis_latency
        }
    except Exception as e:
        is_ready = False
        dependencies["redis"] = {
            "status": "DOWN",
            "error": str(e)
        }

    # 4. WebSocket Manager Check
    ws_connections = len(websocket_manager.active_connections)
    dependencies["websocket"] = {
        "status": "UP",
        "active_connections": ws_connections
    }

    response_payload = {
        "status": "UP" if is_ready else "DOWN",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": dependencies
    }

    if not is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=response_payload
        )

    return response_payload
