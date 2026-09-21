"""SecureMailScope FastAPI Application - Phase 5 Production Hardening."""
import logging
import uuid
import sys
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.routes import health, cases, evidence, analysis, security, intelligence
from app.api.routes import auth

# Setup structured logging
setup_logging()
logger = logging.getLogger(__name__)


APP_VERSION = "0.5.0"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        if settings.enable_security_headers:
            # Prevent MIME type sniffing
            response.headers["X-Content-Type-Options"] = "nosniff"

            # XSS protection
            response.headers["X-XSS-Protection"] = "1; mode=block"

            # Clickjacking protection
            response.headers["X-Frame-Options"] = "DENY"

            # Referrer policy
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

            # Content Security Policy
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "frame-ancestors 'none';"
            )

            # Permissions policy
            response.headers["Permissions-Policy"] = (
                "geolocation=(), microphone=(), camera=()"
            )

            # HSTS (only in production with HTTPS)
            if settings.is_production:
                response.headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains"
                )

        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add request ID to all requests for tracking."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = f"req_{uuid.uuid4().hex[:12]}"

        # Store in request state
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response


def validate_production_config():
    """Validate configuration for production deployment."""
    if settings.is_production:
        errors = settings.validate_production_config()
        if errors:
            for error in errors:
                logger.error(f"Production config error: {error}")
            logger.critical("Production configuration validation failed")
            sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup validation
    validate_production_config()

    # Log startup
    logger.info(
        "Starting SecureMailScope API",
        extra={
            "app": settings.app_name,
            "environment": settings.environment,
            "version": APP_VERSION,
            "debug": settings.debug
        }
    )

    # Initialize admin user if configured
    if settings.admin_password:
        from app.core.database import SessionLocal
        from app.models.user import User, UserRole, UserStatus
        from app.core.security import hash_password

        db = SessionLocal()
        try:
            existing_admin = db.query(User).filter(User.username == settings.admin_username).first()
            if not existing_admin:
                admin_user = User(
                    username=settings.admin_username,
                    email=settings.admin_email,
                    password_hash=hash_password(settings.admin_password),
                    role=UserRole.ADMIN,
                    status=UserStatus.ACTIVE,
                    full_name="System Administrator"
                )
                db.add(admin_user)
                db.commit()
                logger.info(f"Created admin user: {settings.admin_username}")
        except Exception as e:
            logger.warning(f"Could not create admin user: {e}")
        finally:
            db.close()

    yield

    # Shutdown
    logger.info("Shutting down SecureMailScope API")


# Create FastAPI application
app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url="/api/redoc" if settings.debug else None,
    openapi_url="/api/openapi.json" if settings.debug else None
)

# Add security middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)

# Rate limiting (using slowapi)
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
except ImportError:
    logger.warning("slowapi not installed, rate limiting disabled")
    limiter = None

# Include routers
app.include_router(health.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1", tags=["authentication"])
app.include_router(cases.router, prefix="/api/v1/cases")
app.include_router(evidence.router, prefix="/api/v1")
app.include_router(analysis.router, prefix="/api/v1")
app.include_router(security.router, prefix="/api/v1")
app.include_router(intelligence.router, prefix="/api/v1", tags=["intelligence"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    request_id = getattr(request.state, "request_id", "unknown")

    # Log the error
    logger.error(
        f"Unhandled exception: {type(exc).__name__}: {str(exc)}",
        extra={"request_id": request_id},
        exc_info=not settings.is_production  # Only include traceback in non-production
    )

    # Return safe error response
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred" if settings.is_production else str(exc),
                "request_id": request_id
            }
        }
    )


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "SecureMailScope API",
        "version": APP_VERSION,
        "status": "operational",
        "phase": "Phase 5 - Production Hardening"
    }
