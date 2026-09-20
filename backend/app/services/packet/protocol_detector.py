"""Protocol detector for email protocols.

Identifies SMTP, IMAP, and POP3 traffic from packet metadata.
Detection is based on TShark dissector evidence, NOT just port numbers.

IMPORTANT Phase 2 Boundaries:
- This module identifies protocols only
- It does NOT reconstruct TCP streams (Phase 3)
- It does NOT analyze STARTTLS success/failure (Phase 4)
- It does NOT perform TLS security analysis (Phase 5)
"""
import logging
import uuid
from collections import defaultdict
from typing import Iterator

from app.services.packet.models import (
    PacketRecord,
    ProtocolDetection,
    ProtocolSessionCandidate,
    DetectionConfidence,
)

logger = logging.getLogger(__name__)


class ProtocolDetector:
    """
    Detector for email and related protocols.

    Detection strategy:
    1. HIGH confidence: TShark explicitly identifies the protocol
    2. MEDIUM confidence: Multiple indicators (port + pattern)
    3. LOW confidence: Port-based hint only (not definitive)

    Supported protocols:
    - SMTP (ports 25, 587, 465 + TShark detection)
    - IMAP (ports 143, 993 + TShark detection)
    - POP3 (ports 110, 995 + TShark detection)
    - TLS (presence detection only, no security analysis)
    """

    # Protocol names as detected by TShark dissector
    SMTP_PROTOCOLS = {"SMTP", "SMTPS"}
    IMAP_PROTOCOLS = {"IMAP", "IMAPS"}
    POP3_PROTOCOLS = {"POP", "POP3", "POP3S"}
    TLS_PROTOCOLS = {"TLS", "SSL", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

    # Standard ports (hints, not definitive)
    SMTP_PORTS = {25, 465, 587}
    IMAP_PORTS = {143, 993}
    POP3_PORTS = {110, 995}

    def __init__(self):
        """Initialize protocol detector."""
        self._protocol_counts: dict[str, int] = defaultdict(int)
        self._protocol_packets: dict[str, list[PacketRecord]] = defaultdict(list)
        self._stream_protocols: dict[int, set[str]] = defaultdict(set)
        self._session_data: dict[str, dict] = {}

    def reset(self):
        """Reset detector state for a new analysis."""
        self._protocol_counts = defaultdict(int)
        self._protocol_packets = defaultdict(list)
        self._stream_protocols = defaultdict(set)
        self._session_data = {}

    def process_packets(self, packets: Iterator[PacketRecord]) -> None:
        """
        Process packets and collect protocol information.

        Args:
            packets: Iterator of PacketRecord objects
        """
        for packet in packets:
            self._process_packet(packet)

    def _process_packet(self, packet: PacketRecord) -> None:
        """Process a single packet and update protocol state."""
        detected = packet.detected_protocol
        if not detected:
            return

        # Normalize protocol name to uppercase
        protocol_upper = detected.upper()

        # Check for email protocols (TShark dissector detection = HIGH confidence)
        if any(p in protocol_upper for p in self.SMTP_PROTOCOLS):
            self._protocol_counts["SMTP"] += 1
            self._protocol_packets["SMTP"].append(packet)
            if packet.tcp_stream is not None:
                self._stream_protocols[packet.tcp_stream].add("SMTP")

        elif any(p in protocol_upper for p in self.IMAP_PROTOCOLS):
            self._protocol_counts["IMAP"] += 1
            self._protocol_packets["IMAP"].append(packet)
            if packet.tcp_stream is not None:
                self._stream_protocols[packet.tcp_stream].add("IMAP")

        elif any(p in protocol_upper for p in self.POP3_PROTOCOLS):
            self._protocol_counts["POP3"] += 1
            self._protocol_packets["POP3"].append(packet)
            if packet.tcp_stream is not None:
                self._stream_protocols[packet.tcp_stream].add("POP3")

        # Track TLS packets (presence only, no security analysis)
        if any(p in protocol_upper for p in self.TLS_PROTOCOLS):
            self._protocol_counts["TLS"] += 1
            self._protocol_packets["TLS"].append(packet)
            if packet.tcp_stream is not None:
                self._stream_protocols[packet.tcp_stream].add("TLS")

        # Track all protocol occurrences for statistics
        self._protocol_counts[f"_raw_{detected}"] += 1

    def get_detections(self) -> list[ProtocolDetection]:
        """
        Get protocol detection results.

        Returns:
            List of ProtocolDetection objects for detected protocols
        """
        detections = []

        for protocol in ["SMTP", "IMAP", "POP3", "TLS"]:
            count = self._protocol_counts.get(protocol, 0)
            if count > 0:
                packets = self._protocol_packets[protocol]
                first_packet = min(p.packet_number for p in packets) if packets else None
                last_packet = max(p.packet_number for p in packets) if packets else None

                # Collect unique ports
                ports = set()
                for p in packets:
                    if p.dst_port:
                        ports.add(p.dst_port)
                    if p.src_port:
                        ports.add(p.src_port)

                detections.append(ProtocolDetection(
                    protocol=protocol,
                    detection_source="tshark_dissector",
                    confidence=DetectionConfidence.HIGH,
                    packet_count=count,
                    first_seen_packet=first_packet,
                    last_seen_packet=last_packet,
                    ports=sorted(ports)
                ))

        return detections

    def get_session_candidates(self) -> list[ProtocolSessionCandidate]:
        """
        Get protocol session candidates.

        IMPORTANT: These are packet-level groupings, NOT reconstructed TCP streams.
        TCP stream reconstruction is Phase 3.

        Returns:
            List of ProtocolSessionCandidate objects
        """
        candidates = []

        # Group by TCP stream for email protocols
        for stream_id, protocols in self._stream_protocols.items():
            # Get all packets for this stream
            stream_packets = []
            for protocol in ["SMTP", "IMAP", "POP3"]:
                if protocol in protocols:
                    for pkt in self._protocol_packets[protocol]:
                        if pkt.tcp_stream == stream_id:
                            stream_packets.append(pkt)

            if not stream_packets:
                continue

            # Determine primary protocol (most packets)
            protocol_counts = defaultdict(int)
            for pkt in stream_packets:
                detected = pkt.detected_protocol
                if detected:
                    detected_upper = detected.upper()
                    if any(p in detected_upper for p in self.SMTP_PROTOCOLS):
                        protocol_counts["SMTP"] += 1
                    elif any(p in detected_upper for p in self.IMAP_PROTOCOLS):
                        protocol_counts["IMAP"] += 1
                    elif any(p in detected_upper for p in self.POP3_PROTOCOLS):
                        protocol_counts["POP3"] += 1

            if not protocol_counts:
                continue

            primary_protocol = max(protocol_counts.keys(), key=lambda k: protocol_counts[k])

            # Extract session metadata
            first_packet = min(p.packet_number for p in stream_packets)
            last_packet = max(p.packet_number for p in stream_packets)

            # Determine client/server from first packet
            first_pkt = next((p for p in stream_packets if p.packet_number == first_packet), None)
            if first_pkt:
                candidates.append(ProtocolSessionCandidate(
                    candidate_id=f"cand_{uuid.uuid4().hex[:8]}",
                    protocol=primary_protocol,
                    client_ip=first_pkt.src_ip,
                    client_port=first_pkt.src_port,
                    server_ip=first_pkt.dst_ip,
                    server_port=first_pkt.dst_port,
                    packet_count=len(stream_packets),
                    first_packet=first_packet,
                    last_packet=last_packet,
                    tcp_stream=stream_id,
                    detection_confidence=DetectionConfidence.HIGH,
                    detection_source="tshark_dissector"
                ))

        return candidates

    def get_protocol_counts(self) -> dict[str, int]:
        """
        Get counts for each detected email protocol.

        Returns:
            Dictionary with protocol names and packet counts
        """
        return {
            "SMTP": self._protocol_counts.get("SMTP", 0),
            "IMAP": self._protocol_counts.get("IMAP", 0),
            "POP3": self._protocol_counts.get("POP3", 0),
            "TLS": self._protocol_counts.get("TLS", 0),
        }

    def get_email_packet_count(self) -> int:
        """Get total count of email protocol packets."""
        return (
            self._protocol_counts.get("SMTP", 0) +
            self._protocol_counts.get("IMAP", 0) +
            self._protocol_counts.get("POP3", 0)
        )

    def get_detected_protocols(self) -> list[str]:
        """Get list of detected email protocols."""
        protocols = []
        for protocol in ["SMTP", "IMAP", "POP3"]:
            if self._protocol_counts.get(protocol, 0) > 0:
                protocols.append(protocol)
        return protocols

    def has_tls(self) -> bool:
        """Check if TLS traffic was detected."""
        return self._protocol_counts.get("TLS", 0) > 0
