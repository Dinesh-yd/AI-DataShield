from fastapi import APIRouter

from app.api.v1 import alerts, auth, breach, dashboard, remediation, risk, scan

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(scan.router)
api_router.include_router(breach.router)
api_router.include_router(risk.router)
api_router.include_router(alerts.router)
api_router.include_router(dashboard.router)
api_router.include_router(remediation.router)
