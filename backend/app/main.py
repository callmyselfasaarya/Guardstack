import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db
from app.api import repositories, scans, findings, webhooks, dast, benchmark, settings as app_settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("guardstack.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Guardstack ASPM Platform...")
    await init_db()
    logger.info("Database and tables initialized successfully.")
    yield
    logger.info("Guardstack ASPM Platform shutting down.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Intelligent Application Security Posture Management (ASPM) & Automated PR Remediation Platform",
    lifespan=lifespan
)

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(repositories.router, prefix=settings.API_V1_STR)
app.include_router(scans.router, prefix=settings.API_V1_STR)
app.include_router(findings.router, prefix=settings.API_V1_STR)
app.include_router(webhooks.router, prefix=settings.API_V1_STR)
app.include_router(dast.router, prefix=settings.API_V1_STR)
app.include_router(benchmark.router, prefix=settings.API_V1_STR)
app.include_router(app_settings.router, prefix=settings.API_V1_STR)

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "llm_provider": settings.LLM_PROVIDER
    }

import os
from fastapi.staticfiles import StaticFiles

frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")

