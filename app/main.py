from contextlib import asynccontextmanager
import logging
import os
from typing import Any, AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.endpoints import get_health_status, router as api_router
from app.db.mongodb import MongoDBManager, get_db
from app.db.repository import IOCRepository
from app.services.scheduler import feed_scheduler

# Load environment variables from .env if available
load_dotenv()

# Setup logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))
logger = logging.getLogger("threat_intel.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle."""
    logger.info("Initializing Threat Intelligence Feed Integrator...")

    # Initialize MongoDB connection and verify indexes if DB is reachable
    try:
        repo = IOCRepository(get_db())
        await repo.ensure_indexes()
        logger.info("MongoDB connected and collection indexes verified.")
    except Exception as exc:
        logger.warning("MongoDB initial connection deferred or unavailable: %s", exc)

    # Start automated ingestion scheduler
    try:
        feed_scheduler.start()
        logger.info("Threat feed background scheduler active.")
    except Exception as exc:
        logger.warning("Background scheduler failed to start: %s", exc)

    yield

    # Graceful shutdown
    logger.info("Shutting down Threat Intelligence Feed Integrator...")
    try:
        feed_scheduler.shutdown()
    except Exception:
        pass
    MongoDBManager.disconnect()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="Threat Intelligence Feed Integrator API",
    description="Centralized Cyber Threat Intelligence (CTI) Aggregation, Deduplication, and SOC Query API.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for Streamlit and external SOC tool access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes under /api/v1
app.include_router(api_router, prefix="/api/v1")


@app.get("/", tags=["System"])
async def root() -> dict[str, str]:
    """Root metadata endpoint."""
    return {
        "service": "Threat Intelligence Feed Integrator",
        "status": "online",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health", tags=["System"])
async def root_health() -> dict[str, Any]:
    """Root health alias."""
    return await get_health_status()
