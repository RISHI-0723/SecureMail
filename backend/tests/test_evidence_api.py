"""Tests for Evidence API endpoints."""
import io
import hashlib
import tempfile
import pytest
from unittest.mock import patch


class TestEvidenceAPI:
    """Tests for /api/v1/evidence endpoints."""

    def _create_case(self, client):
        """Helper to create a case and return its ID."""
        response = client.post(
            "/api/v1/cases",
            json={"case_name": "Test Case for Evidence"}
        )
        return response.json()["data"]["case_id"]

    def test_upload_valid_pcap(self, client, valid_pcap_bytes, temp_storage_path):
        """Test uploading a valid PCAP file."""
        case_id = self._create_case(client)

        # Mock the storage path
        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )

        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert data["data"]["original_filename"] == "test.pcap"
        assert data["data"]["file_format"] == "pcap"
        assert data["data"]["evidence_status"] == "VALIDATED"
        assert data["data"]["analysis_status"] == "QUEUED"

        # Verify SHA-256
        expected_sha256 = hashlib.sha256(valid_pcap_bytes).hexdigest()
        assert data["data"]["sha256"] == expected_sha256

    def test_upload_valid_pcapng(self, client, valid_pcapng_bytes, temp_storage_path):
        """Test uploading a valid PCAPNG file."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcapng", io.BytesIO(valid_pcapng_bytes), "application/octet-stream")}
            )

        assert response.status_code == 201
        data = response.json()
        assert data["data"]["file_format"] == "pcapng"

    def test_upload_empty_file(self, client, temp_storage_path):
        """Test uploading an empty file."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("empty.pcap", io.BytesIO(b""), "application/octet-stream")}
            )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "EMPTY_FILE"

    def test_upload_invalid_format(self, client, text_file_bytes, temp_storage_path):
        """Test uploading an invalid file format."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("readme.txt", io.BytesIO(text_file_bytes), "text/plain")}
            )

        assert response.status_code == 400
        assert "UNSUPPORTED_FILE_TYPE" in response.json()["detail"]["code"]

    def test_upload_jpg_file(self, client, jpg_file_bytes, temp_storage_path):
        """Test uploading a JPG file (unsupported)."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("image.jpg", io.BytesIO(jpg_file_bytes), "image/jpeg")}
            )

        assert response.status_code == 400
        assert "UNSUPPORTED_FILE_TYPE" in response.json()["detail"]["code"]

    def test_upload_to_nonexistent_case(self, client, valid_pcap_bytes, temp_storage_path):
        """Test uploading to a non-existent case."""
        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            response = client.post(
                "/api/v1/cases/nonexistent_case/evidence",
                files={"file": ("test.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )

        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "CASE_NOT_FOUND"

    def test_upload_no_file(self, client):
        """Test upload without file."""
        case_id = self._create_case(client)

        response = client.post(f"/api/v1/cases/{case_id}/evidence")

        assert response.status_code == 422  # Validation error

    def test_upload_duplicate_evidence(self, client, valid_pcap_bytes, temp_storage_path):
        """Test uploading duplicate evidence (same hash)."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            # First upload
            response1 = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test1.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )
            assert response1.status_code == 201

            # Second upload with same content
            response2 = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test2.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )

        assert response2.status_code == 409
        assert response2.json()["detail"]["code"] == "DUPLICATE_EVIDENCE"

    def test_list_case_evidence_empty(self, client):
        """Test listing evidence when empty."""
        case_id = self._create_case(client)

        response = client.get(f"/api/v1/cases/{case_id}/evidence")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["evidence"] == []
        assert data["data"]["total"] == 0

    def test_list_case_evidence(self, client, valid_pcap_bytes, valid_pcapng_bytes, temp_storage_path):
        """Test listing case evidence."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            # Upload two files
            client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test1.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )
            client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test2.pcapng", io.BytesIO(valid_pcapng_bytes), "application/octet-stream")}
            )

        response = client.get(f"/api/v1/cases/{case_id}/evidence")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["total"] == 2
        assert len(data["data"]["evidence"]) == 2

    def test_list_nonexistent_case_evidence(self, client):
        """Test listing evidence for non-existent case."""
        response = client.get("/api/v1/cases/nonexistent_case/evidence")

        assert response.status_code == 404

    def test_get_evidence(self, client, valid_pcap_bytes, temp_storage_path):
        """Test getting specific evidence."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            upload_response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )
            evidence_id = upload_response.json()["data"]["evidence_id"]

        response = client.get(f"/api/v1/evidence/{evidence_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["evidence_id"] == evidence_id
        assert data["data"]["original_filename"] == "test.pcap"

    def test_get_evidence_not_found(self, client):
        """Test getting non-existent evidence."""
        response = client.get("/api/v1/evidence/nonexistent_evidence")

        assert response.status_code == 404

    def test_delete_evidence(self, client, valid_pcap_bytes, temp_storage_path):
        """Test deleting evidence."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            upload_response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )
            evidence_id = upload_response.json()["data"]["evidence_id"]

            # Delete evidence
            response = client.delete(f"/api/v1/evidence/{evidence_id}")

        assert response.status_code == 200
        assert response.json()["data"]["deleted"] is True

        # Verify evidence is deleted
        get_response = client.get(f"/api/v1/evidence/{evidence_id}")
        assert get_response.status_code == 404

    def test_delete_evidence_not_found(self, client):
        """Test deleting non-existent evidence."""
        response = client.delete("/api/v1/evidence/nonexistent_evidence")

        assert response.status_code == 404

    def test_invalid_pcap_magic_bytes(self, client, temp_storage_path):
        """Test uploading file with .pcap extension but invalid magic bytes."""
        case_id = self._create_case(client)
        invalid_content = b"NotAPCAPFile" + b"\x00" * 100

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            response = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("fake.pcap", io.BytesIO(invalid_content), "application/octet-stream")}
            )

        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "INVALID_PCAP"

    def test_same_filename_different_content(self, client, valid_pcap_bytes, valid_pcapng_bytes, temp_storage_path):
        """Test uploading files with same name but different content."""
        case_id = self._create_case(client)

        with patch("app.services.ingestion.storage.settings") as mock_settings:
            mock_settings.evidence_storage_path = temp_storage_path

            # First upload
            response1 = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcap", io.BytesIO(valid_pcap_bytes), "application/octet-stream")}
            )
            assert response1.status_code == 201
            evidence1_id = response1.json()["data"]["evidence_id"]

            # Second upload with same name but different content (pcapng)
            response2 = client.post(
                f"/api/v1/cases/{case_id}/evidence",
                files={"file": ("test.pcap", io.BytesIO(valid_pcapng_bytes), "application/octet-stream")}
            )
            assert response2.status_code == 201
            evidence2_id = response2.json()["data"]["evidence_id"]

        # Both should be accepted as separate evidence
        assert evidence1_id != evidence2_id
