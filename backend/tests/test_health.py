"""Tests for health check endpoints."""
import pytest
from fastapi.testclient import TestClient


def test_basic_health_check(client: TestClient):
    """Test basic health endpoint returns healthy status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SecureMailScope API"
    assert data["version"] == "0.2.0-phase1"


def test_root_endpoint(client: TestClient):
    """Test root endpoint returns service information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "SecureMailScope API"
    assert data["version"] == "0.2.0-phase1"
    assert data["status"] == "operational"
    assert data["phase"] == "Phase 1 - Evidence Ingestion"


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
