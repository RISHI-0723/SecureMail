"""SecureMailScope FastAPI Application - Phase 0 Foundation."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.routes import health

# Setup structured logging
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info(
        "Starting SecureMailScope API",
        extra={
            "app": settings.app_name,
            "environment": settings.environment,
            "version": "0.1.0-phase0"
        }
    )
    yield
    # Shutdown
    logger.info("Shutting down SecureMailScope API")


# Create FastAPI application
app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
    version="0.1.0-phase0",
    lifespan=lifespan
)

# Configure CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Vite default ports
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "SecureMailScope API",
        "version": "0.1.0-phase0",
        "status": "operational",
        "phase": "Phase 0 - Foundation"
    }
