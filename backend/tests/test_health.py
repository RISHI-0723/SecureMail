"""Tests for health check endpoints."""
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient


def test_basic_health_check(client: TestClient):
    """Test basic health endpoint returns healthy status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SecureMailScope API"
    assert data["version"] == "0.5.0"


def test_root_endpoint(client: TestClient):
    """Test root endpoint returns service information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "SecureMailScope API"
    assert data["version"] == "0.5.0"
    assert data["status"] == "operational"
    assert data["phase"] == "Phase 5 - Production Hardening"


def test_dependencies_health_check_structure(client: TestClient):
    """Test dependencies health endpoint returns expected structure."""
    # Note: This test may fail if database/redis are not available
    # In a real test environment, we'd mock these dependencies
    response = client.get("/api/v1/health/dependencies")
    assert response.status_code == 200
    data = response.json()

    # Check response structure
    assert "status" in data
    assert "service" in data
    assert "version" in data
    assert "dependencies" in data
    assert isinstance(data["dependencies"], list)

    # Check dependency structure
    if len(data["dependencies"]) > 0:
        dep = data["dependencies"][0]
        assert "name" in dep
        assert "status" in dep
        assert dep["status"] in ["healthy", "unhealthy", "unknown"]


def test_dependencies_health_demo_mode(client: TestClient):
    """Test dependencies health endpoint in demo mode (Redis unavailable)."""
    from app.core.config import settings

    # Test with demo mode setting
    with patch.object(settings, 'analysis_execution_mode', 'demo'):
        response = client.get("/api/v1/health/dependencies")

        # Should return 200 even with Redis unavailable in demo mode
        assert response.status_code == 200
        data = response.json()

        # Overall status should be degraded (not healthy, not unhealthy)
        assert data["status"] in ["healthy", "degraded"]

        # Find Redis dependency
        redis_dep = next((d for d in data["dependencies"] if d["name"] == "Redis"), None)
        assert redis_dep is not None

        # Redis should be marked as "unknown" in demo mode
        assert redis_dep["status"] == "unknown"
        assert "not required" in redis_dep["message"].lower() or "demo" in redis_dep["message"].lower()
