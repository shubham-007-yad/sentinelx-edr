from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import setup_logging, logger
from app.api import api_router
from app.api.websocket import router as ws_router
from app.api.health import router as health_router
from app.db.database import Base, engine, SessionLocal
from app.db.init_db import init_db

# Initialize centralized logging with sensitive data masking
setup_logging()

# Create DB tables automatically if they do not exist
try:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        init_db(db)
    finally:
        db.close()
    logger.info("Database initialized successfully.")
except Exception as e:
    logger.warning("Could not connect to database on startup. Ensure DB is running and credentials are valid.")

api_prefix = settings.API_V1_STR if settings.API_V1_STR.startswith("/") else f"/{settings.API_V1_STR}"
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{api_prefix}/openapi.json"
)

# CORS middleware configuration using centralized CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(health_router)
app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(ws_router)

@app.get("/")
def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "docs": f"{settings.API_V1_STR}/openapi.json"
    }
