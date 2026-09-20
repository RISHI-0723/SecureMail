"""Tests for Analysis API endpoints."""
import io
import pytest
from unittest.mock import patch


class TestAnalysisAPI:
    """Tests for /api/v1/analysis endpoints."""

    def _create_case_with_evidence(self, client, pcap_bytes, temp_storage_path):
        """Helper to create a case with evidence."""
        # Create case
        case_response = client.post(
            "/api/v1/cases",
            json={"case_name": "Test Case"}
        )
        case_id = case_response.json()["data"]["case_id"]

        # Upload evidence
        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            evidence_response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcap", io.BytesIO(pcap_bytes), "application/octet-stream")}
            )

        evidence_data = evidence_response.json()["data"]
        return {
            "case_id": case_id,
            "evidence_id": evidence_data["evidence_id"],
            "job_id": evidence_data["analysis_job_id"]
        }

    def test_get_analysis_job(self, client, valid_pcap_bytes, temp_storage_path):
        """Test getting an analysis job."""
        data = self._create_case_with_evidence(client, valid_pcap_bytes, temp_storage_path)

        response = client.get(f"/api/v1/analysis/{data['job_id']}")

        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert result["data"]["job_id"] == data["job_id"]
        assert result["data"]["evidence_id"] == data["evidence_id"]
        assert result["data"]["status"] == "QUEUED"
        assert result["data"]["job_type"] == "FULL_ANALYSIS"

    def test_get_analysis_job_not_found(self, client):
        """Test getting a non-existent analysis job."""
        response = client.get("/api/v1/analysis/nonexistent_job")

        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "ANALYSIS_JOB_NOT_FOUND"

    def test_get_evidence_analysis_jobs(self, client, valid_pcap_bytes, temp_storage_path):
        """Test getting analysis jobs for evidence."""
        data = self._create_case_with_evidence(client, valid_pcap_bytes, temp_storage_path)

        response = client.get(f"/api/v1/evidence/{data['evidence_id']}/analysis")

        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert result["data"]["total"] == 1
        assert len(result["data"]["jobs"]) == 1
        assert result["data"]["jobs"][0]["job_id"] == data["job_id"]

    def test_get_evidence_analysis_jobs_not_found(self, client):
        """Test getting analysis jobs for non-existent evidence."""
        response = client.get("/api/v1/evidence/nonexistent_evidence/analysis")

        assert response.status_code == 404

    def test_list_analysis_jobs_empty(self, client):
        """Test listing analysis jobs when empty."""
        response = client.get("/api/v1/analysis")

        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert result["data"]["jobs"] == []
        assert result["data"]["total"] == 0

    def test_list_analysis_jobs(self, client, valid_pcap_bytes, valid_pcapng_bytes, temp_storage_path):
        """Test listing all analysis jobs."""
        # Create two pieces of evidence (creates two jobs)
        case_response = client.post(
            "/api/v1/cases",
            json={"case_name": "Test Case"}
        )
        case_id = case_response.json()["data"]["case_id"]

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test1.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )
            client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test2.pcapng", io.BytesIO(valid_pcapng_bytes), "application/octet-stream")}
            )

        response = client.get("/api/v1/analysis")

        assert response.status_code == 200
        result = response.json()
        assert result["data"]["total"] == 2
        assert len(result["data"]["jobs"]) == 2

    def test_list_analysis_jobs_with_filter(self, client, valid_pcap_bytes, temp_storage_path):
        """Test filtering analysis jobs by status."""
        self._create_case_with_evidence(client, valid_pcap_bytes, temp_storage_path)

        # All jobs should be QUEUED
        response = client.get("/api/v1/analysis?status_filter=QUEUED")

        assert response.status_code == 200
        result = response.json()
        assert result["data"]["total"] >= 1
        for job in result["data"]["jobs"]:
            assert job["status"] == "QUEUED"

        # No COMPLETED jobs
        response_empty = client.get("/api/v1/analysis?status_filter=COMPLETED")
        assert response_empty.json()["data"]["total"] == 0

    def test_analysis_job_initial_state(self, client, valid_pcap_bytes, temp_storage_path):
        """Test initial state of analysis job after evidence upload."""
        data = self._create_case_with_evidence(client, valid_pcap_bytes, temp_storage_path)

        response = client.get(f"/api/v1/analysis/{data['job_id']}")
        job = response.json()["data"]

        # Verify Phase 1 initial state
        assert job["status"] == "QUEUED"
        assert job["started_at"] is None
        assert job["completed_at"] is None
        assert job["error_code"] is None
        assert job["error_message"] is None
        assert job["progress_percent"] == "0"
        assert job["stage"] is None
