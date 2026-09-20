"""TCP stream reconstruction models.

Phase 3: Provides data structures for TCP stream analysis.

IMPORTANT: Stream integrity classification is mandatory.
Never silently treat PARTIAL as COMPLETE.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class StreamIntegrity(str, Enum):
    """
    TCP stream integrity classification.

    COMPLETE: Stream reconstructed without known missing sequence ranges,
              terminates normally or has sufficient complete evidence.
    PARTIAL: Known missing data exists, capture ends before stream is complete,
             or only part of the conversation is captured.
    CORRUPTED: Evidence contains contradictions or reconstruction conditions
               that prevent trustworthy interpretation.
    UNKNOWN: Insufficient evidence to determine integrity.
    """
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    CORRUPTED = "CORRUPTED"
    UNKNOWN = "UNKNOWN"


class StreamTermination(str, Enum):
    """How a TCP stream was terminated."""
    FIN = "FIN"           # Clean FIN close
    RST = "RST"           # RST termination
    TIMEOUT = "TIMEOUT"   # Connection timeout (inferred)
    TRUNCATED = "TRUNCATED"  # Capture ended during stream
    UNKNOWN = "UNKNOWN"


class SequenceRange(BaseModel):
    """A range of TCP sequence numbers."""
    start: int = Field(description="Start sequence number")
    end: int = Field(description="End sequence number (exclusive)")


class TcpStreamData(BaseModel):
    """
    Reconstructed TCP stream data.

    Contains metadata about a TCP stream and optionally
    directional byte content for protocol analysis.

    NOTE: Full payload data should NOT be persisted permanently
    to minimize privacy/storage concerns.
    """
    stream_id: int = Field(description="TShark TCP stream identifier")
    protocol: Optional[str] = Field(default=None, description="Detected protocol (SMTP, IMAP, POP3)")

    # Client/Server identification
    client_ip: Optional[str] = Field(default=None, description="Client IP address")
    client_port: Optional[int] = Field(default=None, description="Client port")
    server_ip: Optional[str] = Field(default=None, description="Server IP address")
    server_port: Optional[int] = Field(default=None, description="Server port")

    # Timing
    start_time: Optional[datetime] = Field(default=None, description="First packet timestamp")
    end_time: Optional[datetime] = Field(default=None, description="Last packet timestamp")

    # Packet statistics
    packet_count: int = Field(default=0, description="Total packets in stream")
    client_packets: int = Field(default=0, description="Packets from client")
    server_packets: int = Field(default=0, description="Packets from server")
    first_packet: Optional[int] = Field(default=None, description="First packet number")
    last_packet: Optional[int] = Field(default=None, description="Last packet number")

    # Stream integrity
    integrity: StreamIntegrity = Field(
        default=StreamIntegrity.UNKNOWN,
        description="Stream reconstruction integrity"
    )
    termination: StreamTermination = Field(
        default=StreamTermination.UNKNOWN,
        description="How stream was terminated"
    )

    # Quality metrics
    retransmission_count: int = Field(default=0, description="Detected retransmissions")
    out_of_order_count: int = Field(default=0, description="Out-of-order packets")
    duplicate_count: int = Field(default=0, description="Duplicate segments")
    missing_ranges: list[SequenceRange] = Field(
        default_factory=list,
        description="Missing sequence ranges"
    )

    # Directional data (not persisted, used transiently for analysis)
    client_to_server_bytes: Optional[bytes] = Field(
        default=None,
        exclude=True,
        description="Reconstructed client->server payload (transient)"
    )
    server_to_client_bytes: Optional[bytes] = Field(
        default=None,
        exclude=True,
        description="Reconstructed server->client payload (transient)"
    )

    # Analysis flags
    has_tls: bool = Field(default=False, description="TLS traffic detected in stream")
    tls_transition_detected: bool = Field(
        default=False,
        description="STARTTLS/STLS transition detected"
    )


class TcpStreamResult(BaseModel):
    """Result of TCP stream reconstruction for an evidence file."""
    evidence_id: str = Field(description="Evidence identifier")
    job_id: str = Field(description="Analysis job identifier")

    # Reconstruction results
    streams: list[TcpStreamData] = Field(
        default_factory=list,
        description="Reconstructed TCP streams"
    )
    total_streams: int = Field(default=0, description="Total streams found")
    email_streams: int = Field(default=0, description="Email protocol streams")

    # Coverage assessment
    complete_streams: int = Field(default=0, description="Streams with COMPLETE integrity")
    partial_streams: int = Field(default=0, description="Streams with PARTIAL integrity")
    corrupted_streams: int = Field(default=0, description="Streams with CORRUPTED integrity")
    unknown_streams: int = Field(default=0, description="Streams with UNKNOWN integrity")

    # Error information
    error_code: Optional[str] = Field(default=None, description="Error code if failed")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")
