from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.devices import router as devices_router
from app.api.usb import router as usb_router
from app.api.threats import router as threats_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(devices_router)
api_router.include_router(usb_router)
api_router.include_router(threats_router)

__all__ = ["api_router"]

