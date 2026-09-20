"""Analysis job schemas for API requests and responses."""
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

from app.models.analysis_job import JobStatus, JobType


class AnalysisJobResponse(BaseModel):
    """Response schema for analysis job."""
    model_config = ConfigDict(from_attributes=True)

    job_id: str = Field(description="Unique job identifier")
    evidence_id: str = Field(description="Associated evidence identifier")
    job_type: JobType = Field(description="Type of analysis job")
    status: JobStatus = Field(description="Current job status")
    created_at: datetime = Field(description="Job creation timestamp")
    started_at: datetime | None = Field(description="Job start timestamp")
    completed_at: datetime | None = Field(description="Job completion timestamp")
    error_code: str | None = Field(default=None, description="Error code if failed")
    error_message: str | None = Field(default=None, description="Error message if failed")
    progress_percent: str | None = Field(default=None, description="Progress percentage")
    stage: str | None = Field(default=None, description="Current processing stage")


class AnalysisJobListResponse(BaseModel):
    """Response schema for job listing."""
    jobs: list[AnalysisJobResponse] = Field(description="List of analysis jobs")
    total: int = Field(description="Total number of jobs")


# Phase 2: Packet Analysis Schemas

class ProtocolDetectionResponse(BaseModel):
    """Protocol detection result."""
    protocol: str = Field(description="Protocol name (SMTP, IMAP, POP3, TLS)")
    detection_source: str = Field(description="How the protocol was detected")
    confidence: str = Field(description="Detection confidence (HIGH, MEDIUM, LOW)")
    packet_count: int = Field(description="Number of packets for this protocol")
    first_seen_packet: int | None = Field(default=None, description="First packet number")
    last_seen_packet: int | None = Field(default=None, description="Last packet number")
    ports: list[int] = Field(default_factory=list, description="Ports observed")


class SessionCandidateResponse(BaseModel):
    """Protocol session candidate (packet grouping, NOT TCP reconstruction)."""
    candidate_id: str = Field(description="Candidate identifier")
    protocol: str = Field(description="Primary protocol")
    client_ip: str | None = Field(default=None, description="Client IP address")
    client_port: int | None = Field(default=None, description="Client port")
    server_ip: str | None = Field(default=None, description="Server IP address")
    server_port: int | None = Field(default=None, description="Server port")
    packet_count: int = Field(description="Number of packets")
    first_packet: int | None = Field(default=None, description="First packet number")
    last_packet: int | None = Field(default=None, description="Last packet number")
    tcp_stream: int | None = Field(default=None, description="TCP stream identifier")
    detection_confidence: str = Field(description="Detection confidence")
    detection_source: str = Field(description="Detection source")


class PacketAnalysisSummaryResponse(BaseModel):
    """Packet analysis summary for Phase 2."""
    model_config = ConfigDict(from_attributes=True)

    analysis_id: str = Field(description="Analysis record identifier")
    job_id: str = Field(description="Associated job identifier")
    evidence_id: str = Field(description="Associated evidence identifier")
    status: str = Field(description="Analysis status")

    # TShark metadata
    tshark_version: str | None = Field(default=None, description="TShark version used")
    analysis_timestamp: datetime = Field(description="When analysis was performed")
    duration_seconds: float | None = Field(default=None, description="Analysis duration")

    # Packet counts
    total_packets: int = Field(description="Total packets in capture")
    email_packets: int = Field(description="Email protocol packets")
    smtp_packets: int = Field(description="SMTP packets")
    imap_packets: int = Field(description="IMAP packets")
    pop3_packets: int = Field(description="POP3 packets")
    tls_packets: int = Field(description="TLS packets")
    other_packets: int = Field(description="Other packets")

    # Protocol information
    protocols_detected: list[str] = Field(description="List of detected protocols")
    protocol_detections: list[ProtocolDetectionResponse] = Field(
        default_factory=list,
        description="Detailed protocol detections"
    )
    session_candidates: list[SessionCandidateResponse] = Field(
        default_factory=list,
        description="Protocol session candidates"
    )

    # Message
    message: str | None = Field(default=None, description="Human-readable summary")


class ProtocolSummaryResponse(BaseModel):
    """Protocol detection summary."""
    protocols_detected: list[str] = Field(description="List of detected protocols")
    protocol_counts: dict[str, int] = Field(description="Packet counts per protocol")
    total_email_packets: int = Field(description="Total email protocol packets")
    has_tls: bool = Field(description="Whether TLS traffic was detected")
    session_count: int = Field(description="Number of session candidates")


class TriggerAnalysisResponse(BaseModel):
    """Response after triggering analysis."""
    job_id: str = Field(description="Job identifier")
    status: str = Field(description="Current job status")
    message: str = Field(description="Status message")
