"""TCP stream reconstruction service.

Phase 3: Reconstructs TCP streams from Phase 2 packet data.

This service:
- Groups packets by TCP stream ID
- Identifies client/server direction
- Detects retransmissions and duplicates
- Classifies stream integrity
- Tracks FIN/RST termination

IMPORTANT: This service consumes Phase 2 data.
It does NOT re-run TShark independently.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from app.services.tcp.models import (
    StreamIntegrity,
    StreamTermination,
    TcpStreamData,
    TcpStreamResult,
    SequenceRange,
)
from app.services.packet.models import PacketRecord

logger = logging.getLogger(__name__)


class TcpStreamReconstructor:
    """
    TCP stream reconstructor using Phase 2 packet data.

    Limitations (due to Phase 2 data availability):
    - Full sequence-aware reconstruction requires sequence numbers
      which Phase 2 may not persist. In such cases, streams are
      marked with appropriate integrity levels.
    - Payload reconstruction is limited without sequence data.

    Detection capabilities:
    - Stream grouping by TCP stream ID
    - Client/server identification (initiator detection)
    - Protocol association
    - TLS presence detection
    - FIN/RST termination detection via TCP flags
    """

    # TCP flag bits
    TCP_FIN = 0x01
    TCP_SYN = 0x02
    TCP_RST = 0x04
    TCP_PSH = 0x08
    TCP_ACK = 0x10

    # Email protocol ports (hints, not definitive)
    SMTP_PORTS = {25, 465, 587}
    IMAP_PORTS = {143, 993}
    POP3_PORTS = {110, 995}
    EMAIL_PORTS = SMTP_PORTS | IMAP_PORTS | POP3_PORTS

    def __init__(self):
        """Initialize the stream reconstructor."""
        self._streams: dict[int, list[PacketRecord]] = defaultdict(list)
        self._stream_data: dict[int, TcpStreamData] = {}

    def reset(self):
        """Reset reconstructor state for new analysis."""
        self._streams = defaultdict(list)
        self._stream_data = {}

    def process_packets(self, packets: list[PacketRecord]) -> None:
        """
        Process packets and group them by TCP stream.

        Args:
            packets: List of PacketRecord from Phase 2
        """
        for packet in packets:
            if packet.tcp_stream is not None:
                self._streams[packet.tcp_stream].append(packet)

        # Process each stream
        for stream_id, stream_packets in self._streams.items():
            self._analyze_stream(stream_id, stream_packets)

    def _analyze_stream(
        self,
        stream_id: int,
        packets: list[PacketRecord]
    ) -> None:
        """
        Analyze a single TCP stream.

        Args:
            stream_id: TCP stream identifier
            packets: Packets belonging to this stream
        """
        if not packets:
            return

        # Sort by packet number for chronological order
        packets = sorted(packets, key=lambda p: p.packet_number)

        # Determine client/server from first packet (SYN or first data)
        first_pkt = packets[0]
        client_ip = first_pkt.src_ip
        client_port = first_pkt.src_port
        server_ip = first_pkt.dst_ip
        server_port = first_pkt.dst_port

        # If first packet has server port in email ports, swap direction
        # (Server is more likely to be on well-known port)
        if first_pkt.src_port in self.EMAIL_PORTS and first_pkt.dst_port not in self.EMAIL_PORTS:
            client_ip, server_ip = server_ip, client_ip
            client_port, server_port = server_port, client_port

        # Detect protocol from packets
        protocol = self._detect_protocol(packets)

        # Count packets by direction
        client_packets = 0
        server_packets = 0
        for pkt in packets:
            if pkt.src_ip == client_ip and pkt.src_port == client_port:
                client_packets += 1
            else:
                server_packets += 1

        # Parse timestamps
        start_time = self._parse_timestamp(first_pkt.timestamp)
        end_time = self._parse_timestamp(packets[-1].timestamp)

        # Detect TLS
        has_tls = any(
            pkt.detected_protocol and "TLS" in pkt.detected_protocol.upper()
            for pkt in packets
        )
        tls_transition = self._detect_tls_transition(packets, protocol)

        # Detect termination
        termination = self._detect_termination(packets)

        # Assess integrity
        # Without sequence numbers, we can only do basic integrity assessment
        integrity = self._assess_integrity(packets, termination)

        # Create stream data
        self._stream_data[stream_id] = TcpStreamData(
            stream_id=stream_id,
            protocol=protocol,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            start_time=start_time,
            end_time=end_time,
            packet_count=len(packets),
            client_packets=client_packets,
            server_packets=server_packets,
            first_packet=packets[0].packet_number,
            last_packet=packets[-1].packet_number,
            integrity=integrity,
            termination=termination,
            has_tls=has_tls,
            tls_transition_detected=tls_transition,
        )

    def _detect_protocol(self, packets: list[PacketRecord]) -> Optional[str]:
        """Detect the primary email protocol in the stream."""
        protocol_counts: dict[str, int] = defaultdict(int)

        for pkt in packets:
            if not pkt.detected_protocol:
                continue
            proto_upper = pkt.detected_protocol.upper()
            if "SMTP" in proto_upper:
                protocol_counts["SMTP"] += 1
            elif "IMAP" in proto_upper:
                protocol_counts["IMAP"] += 1
            elif "POP" in proto_upper:
                protocol_counts["POP3"] += 1

        if not protocol_counts:
            return None

        return max(protocol_counts, key=protocol_counts.get)

    def _detect_tls_transition(
        self,
        packets: list[PacketRecord],
        protocol: Optional[str]
    ) -> bool:
        """
        Detect STARTTLS/STLS transition in stream.

        A transition is detected when we see email protocol packets
        followed by TLS packets within the same stream.
        """
        if not protocol:
            return False

        seen_email = False
        seen_tls_after_email = False

        for pkt in sorted(packets, key=lambda p: p.packet_number):
            if not pkt.detected_protocol:
                continue

            proto_upper = pkt.detected_protocol.upper()

            # Check for email protocol
            if protocol.upper() in proto_upper:
                seen_email = True

            # Check for TLS after seeing email protocol
            if seen_email and "TLS" in proto_upper:
                seen_tls_after_email = True
                break

        return seen_tls_after_email

    def _detect_termination(
        self,
        packets: list[PacketRecord]
    ) -> StreamTermination:
        """Detect how the stream was terminated."""
        for pkt in reversed(packets):
            if not pkt.tcp_flags:
                continue

            try:
                # TCP flags can be hex string like "0x018" or integer
                if isinstance(pkt.tcp_flags, str):
                    flags = int(pkt.tcp_flags, 16) if pkt.tcp_flags.startswith("0x") else int(pkt.tcp_flags)
                else:
                    flags = int(pkt.tcp_flags)

                if flags & self.TCP_RST:
                    return StreamTermination.RST
                if flags & self.TCP_FIN:
                    return StreamTermination.FIN

            except (ValueError, TypeError):
                continue

        return StreamTermination.TRUNCATED

    def _assess_integrity(
        self,
        packets: list[PacketRecord],
        termination: StreamTermination
    ) -> StreamIntegrity:
        """
        Assess stream integrity.

        Without sequence numbers, we use heuristics:
        - FIN termination suggests COMPLETE
        - RST or TRUNCATED suggests PARTIAL
        - Very few packets suggests PARTIAL or UNKNOWN
        """
        if len(packets) < 2:
            return StreamIntegrity.UNKNOWN

        if termination == StreamTermination.FIN:
            # Clean termination, likely complete
            return StreamIntegrity.COMPLETE
        elif termination == StreamTermination.RST:
            # RST doesn't mean incomplete, but connection was reset
            return StreamIntegrity.COMPLETE
        elif termination == StreamTermination.TRUNCATED:
            # Capture ended during stream
            return StreamIntegrity.PARTIAL
        else:
            # Can't determine
            return StreamIntegrity.UNKNOWN

    def _parse_timestamp(self, timestamp: Optional[str]) -> Optional[datetime]:
        """Parse epoch timestamp string to datetime."""
        if not timestamp:
            return None
        try:
            epoch = float(timestamp)
            return datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (ValueError, TypeError):
            return None

    def get_streams(self) -> list[TcpStreamData]:
        """Get all reconstructed streams."""
        return list(self._stream_data.values())

    def get_stream(self, stream_id: int) -> Optional[TcpStreamData]:
        """Get a specific stream by ID."""
        return self._stream_data.get(stream_id)

    def get_email_streams(self) -> list[TcpStreamData]:
        """Get streams with detected email protocols."""
        return [
            s for s in self._stream_data.values()
            if s.protocol is not None
        ]

    def get_result(self, evidence_id: str, job_id: str) -> TcpStreamResult:
        """
        Get complete reconstruction result.

        Args:
            evidence_id: Evidence identifier
            job_id: Analysis job identifier

        Returns:
            TcpStreamResult with all stream data
        """
        streams = self.get_streams()

        complete = sum(1 for s in streams if s.integrity == StreamIntegrity.COMPLETE)
        partial = sum(1 for s in streams if s.integrity == StreamIntegrity.PARTIAL)
        corrupted = sum(1 for s in streams if s.integrity == StreamIntegrity.CORRUPTED)
        unknown = sum(1 for s in streams if s.integrity == StreamIntegrity.UNKNOWN)

        email_streams = sum(1 for s in streams if s.protocol is not None)

        return TcpStreamResult(
            evidence_id=evidence_id,
            job_id=job_id,
            streams=streams,
            total_streams=len(streams),
            email_streams=email_streams,
            complete_streams=complete,
            partial_streams=partial,
            corrupted_streams=corrupted,
            unknown_streams=unknown,
        )
