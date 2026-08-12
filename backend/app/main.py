from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import Base, engine
from app.services.monitor import breach_monitor

Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.app_name)

origins = [item.strip() for item in settings.allowed_origins.split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.api_prefix)

frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
if frontend_dir.exists():
    app.mount("/frontend", StaticFiles(directory=str(frontend_dir)), name="frontend")


@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}


@app.get("/")
def index():
    index_file = frontend_dir / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "AI DataShield API is running"}


@app.on_event("startup")
async def _startup_monitor():
    await breach_monitor.start()


@app.on_event("shutdown")
async def _shutdown_monitor():
    await breach_monitor.stop()
