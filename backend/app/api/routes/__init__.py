"""API route modules."""
from app.api.routes.health import router as health_router
from app.api.routes.cases import router as cases_router
from app.api.routes.evidence import router as evidence_router
from app.api.routes.analysis import router as analysis_router

__all__ = [
    "health_router",
    "cases_router",
    "evidence_router",
    "analysis_router",
]
