"""Pydantic models for packet analysis data structures.

These models represent packet-level metadata and protocol detection results.
Phase 2 focuses on packet extraction and protocol identification only.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class TSharkStatus(str, Enum):
    """Status of a TShark execution."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    NOT_FOUND = "NOT_FOUND"


class DetectionConfidence(str, Enum):
    """Confidence level for protocol detection."""
    HIGH = "HIGH"      # TShark explicitly identifies the protocol
    MEDIUM = "MEDIUM"  # Multiple packet-level indicators
    LOW = "LOW"        # Only weak indirect evidence (e.g., port-based)


class TSharkResult(BaseModel):
    """Result of a TShark execution."""
    status: TSharkStatus
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_seconds: Optional[float] = None
    tshark_version: Optional[str] = None


class PacketRecord(BaseModel):
    """
    Structured representation of a single packet.

    Contains packet-level metadata extracted from TShark.
    Not all fields are always available - missing fields become None.
    """
    packet_number: int
    timestamp: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport_protocol: Optional[str] = None  # TCP, UDP, etc.
    detected_protocol: Optional[str] = None   # SMTP, IMAP, POP3, TLS, HTTP, etc.
    packet_length: Optional[int] = None
    tcp_stream: Optional[int] = None
    tcp_flags: Optional[str] = None
    ip_version: Optional[int] = None
    frame_protocols: Optional[str] = None  # Protocol stack (e.g., "eth:ip:tcp:smtp")


class ProtocolDetection(BaseModel):
    """
    Detection result for a specific protocol.

    Captures protocol identification with confidence level and evidence.
    """
    protocol: str
    detection_source: str  # "tshark_dissector", "port_hint", etc.
    confidence: DetectionConfidence
    packet_count: int
    first_seen_packet: Optional[int] = None
    last_seen_packet: Optional[int] = None
    ports: list[int] = Field(default_factory=list)


class ProtocolSessionCandidate(BaseModel):
    """
    A packet-level grouping representing a potential protocol session.

    IMPORTANT: This is NOT a reconstructed TCP stream.
    These are packet-level groupings/candidates only.
    TCP stream reconstruction is Phase 3.
    """
    candidate_id: str
    protocol: str
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_ip: Optional[str] = None
    server_port: Optional[int] = None
    packet_count: int
    first_packet: Optional[int] = None
    last_packet: Optional[int] = None
    tcp_stream: Optional[int] = None
    detection_confidence: DetectionConfidence
    detection_source: str


class PacketAnalysisSummary(BaseModel):
    """
    Summary of packet analysis for an evidence file.

    Contains aggregate counts and detected protocols.
    All values come from actual TShark analysis.
    """
    evidence_id: str
    job_id: str
    status: str  # COMPLETED, FAILED, etc.
    tshark_version: Optional[str] = None
    analysis_timestamp: datetime
    duration_seconds: Optional[float] = None

    # Packet counts
    total_packets: int = 0
    email_packets: int = 0
    smtp_packets: int = 0
    imap_packets: int = 0
    pop3_packets: int = 0
    tls_packets: int = 0
    other_packets: int = 0

    # Detected protocols
    protocols_detected: list[str] = Field(default_factory=list)
    protocol_detections: list[ProtocolDetection] = Field(default_factory=list)
    session_candidates: list[ProtocolSessionCandidate] = Field(default_factory=list)

    # Error information (if analysis failed)
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    # Analysis metadata
    message: Optional[str] = None  # e.g., "No supported email protocols detected."
