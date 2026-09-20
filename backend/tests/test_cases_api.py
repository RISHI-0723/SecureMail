"""Tests for Cases API endpoints."""
import pytest


class TestCasesAPI:
    """Tests for /api/v1/cases endpoints."""

    def test_create_case(self, client):
        """Test case creation."""
        response = client.post(
            "/api/v1/cases",
            json={
                "case_name": "Test Case",
                "description": "Test description"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert data["data"]["case_name"] == "Test Case"
        assert data["data"]["description"] == "Test description"
        assert data["data"]["status"] == "OPEN"
        assert "case_id" in data["data"]

    def test_create_case_minimal(self, client):
        """Test case creation with minimal data."""
        response = client.post(
            "/api/v1/cases",
            json={"case_name": "Minimal Case"}
        )

        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert data["data"]["case_name"] == "Minimal Case"
        assert data["data"]["description"] is None

    def test_create_case_invalid(self, client):
        """Test case creation with invalid data."""
        response = client.post(
            "/api/v1/cases",
            json={}  # Missing required field
        )

        assert response.status_code == 422  # Validation error

    def test_list_cases_empty(self, client):
        """Test listing cases when empty."""
        response = client.get("/api/v1/cases")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["cases"] == []
        assert data["data"]["total"] == 0

    def test_list_cases(self, client):
        """Test listing cases."""
        # Create some cases
        client.post("/api/v1/cases", json={"case_name": "Case 1"})
        client.post("/api/v1/cases", json={"case_name": "Case 2"})

        response = client.get("/api/v1/cases")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["total"] == 2
        assert len(data["data"]["cases"]) == 2

    def test_get_case(self, client):
        """Test getting a specific case."""
        # Create a case
        create_response = client.post(
            "/api/v1/cases",
            json={"case_name": "Test Case"}
        )
        case_id = create_response.json()["data"]["case_id"]

        # Get the case
        response = client.get(f"/api/v1/cases/{case_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["case_id"] == case_id
        assert data["data"]["case_name"] == "Test Case"

    def test_get_case_not_found(self, client):
        """Test getting a non-existent case."""
        response = client.get("/api/v1/cases/nonexistent_id")

        assert response.status_code == 404
        data = response.json()
        assert data["detail"]["code"] == "CASE_NOT_FOUND"

    def test_update_case(self, client):
        """Test updating a case."""
        # Create a case
        create_response = client.post(
            "/api/v1/cases",
            json={"case_name": "Original Name"}
        )
        case_id = create_response.json()["data"]["case_id"]

        # Update the case
        response = client.patch(
            f"/api/v1/cases/{case_id}",
            json={"case_name": "Updated Name", "description": "New description"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["case_name"] == "Updated Name"
        assert data["data"]["description"] == "New description"

    def test_update_case_not_found(self, client):
        """Test updating a non-existent case."""
        response = client.patch(
            "/api/v1/cases/nonexistent_id",
            json={"case_name": "Updated Name"}
        )

        assert response.status_code == 404

    def test_delete_case(self, client):
        """Test deleting a case."""
        # Create a case
        create_response = client.post(
            "/api/v1/cases",
            json={"case_name": "To Delete"}
        )
        case_id = create_response.json()["data"]["case_id"]

        # Delete the case
        response = client.delete(f"/api/v1/cases/{case_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["deleted"] is True

        # Verify case is deleted
        get_response = client.get(f"/api/v1/cases/{case_id}")
        assert get_response.status_code == 404

    def test_delete_case_not_found(self, client):
        """Test deleting a non-existent case."""
        response = client.delete("/api/v1/cases/nonexistent_id")

        assert response.status_code == 404

    def test_case_evidence_count(self, client, valid_pcap_bytes):
        """Test evidence count in case response."""
        # Create a case
        create_response = client.post(
            "/api/v1/cases",
            json={"case_name": "Test Case"}
        )
        case_id = create_response.json()["data"]["case_id"]

        # Initially should have 0 evidence
        response = client.get(f"/api/v1/cases/{case_id}")
        assert response.json()["data"]["evidence_count"] == 0
