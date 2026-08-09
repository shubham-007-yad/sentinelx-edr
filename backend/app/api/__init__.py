from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.devices import router as devices_router
from app.api.usb import router as usb_router
from app.api.threats import router as threats_router
from app.api.websocket import router as ws_router
from app.api.alerts import router as alerts_router
from app.api.responses import router as responses_router
from app.api.processes import router as processes_router
from app.api.network import router as network_router
from app.api.file_integrity import router as fim_router
from app.api.event_logs import router as event_logs_router
from app.api.telemetry import router as telemetry_router
from app.api.ransomware import router as ransomware_router
from app.api.investigation import router as investigation_router
from app.api.policies import router as policies_router
from app.api.analytics import router as analytics_router
from app.api.scheduled_reports import router as scheduled_reports_router
from app.api.fleet import router as fleet_router
from app.api.jobs import router as jobs_router
from app.api.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(devices_router)
api_router.include_router(usb_router)
api_router.include_router(threats_router)
api_router.include_router(alerts_router)
api_router.include_router(responses_router)
api_router.include_router(processes_router)
api_router.include_router(network_router)
api_router.include_router(fim_router)
api_router.include_router(event_logs_router)
api_router.include_router(telemetry_router)
api_router.include_router(ransomware_router)
api_router.include_router(investigation_router)
api_router.include_router(policies_router)
api_router.include_router(analytics_router)
api_router.include_router(scheduled_reports_router)
api_router.include_router(fleet_router)
api_router.include_router(jobs_router)
api_router.include_router(ws_router)

__all__ = ["api_router"]
