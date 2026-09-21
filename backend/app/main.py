"""SecureMailScope FastAPI Application - Phase 4 Intelligence & Reporting."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.routes import health, cases, evidence, analysis, security, intelligence

# Setup structured logging
setup_logging()
logger = logging.getLogger(__name__)


APP_VERSION = "0.4.0-phase4"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info(
        "Starting SecureMailScope API",
        extra={
            "app": settings.app_name,
            "environment": settings.environment,
            "version": APP_VERSION
        }
    )
    yield
    # Shutdown
    logger.info("Shutting down SecureMailScope API")


# Create FastAPI application
app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
    version=APP_VERSION,
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
app.include_router(cases.router, prefix="/api/v1/cases")
app.include_router(evidence.router, prefix="/api/v1")
app.include_router(analysis.router, prefix="/api/v1")
app.include_router(security.router, prefix="/api/v1")
app.include_router(intelligence.router, prefix="/api/v1", tags=["intelligence"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "SecureMailScope API",
        "version": APP_VERSION,
        "status": "operational",
        "phase": "Phase 4 - Intelligence & Reporting"
    }
