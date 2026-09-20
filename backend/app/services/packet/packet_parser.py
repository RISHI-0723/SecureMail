"""Packet parser for TShark output.

Parses structured TShark output into PacketRecord objects.
Handles missing fields, malformed rows, and edge cases gracefully.
"""
import logging
from typing import Iterator, Optional

from app.services.packet.models import PacketRecord, TSharkResult, TSharkStatus

logger = logging.getLogger(__name__)


class PacketParser:
    """
    Parser for TShark tabular output.

    Converts TShark -T fields output into structured PacketRecord objects.
    Tolerates:
    - Missing fields (become None)
    - Empty fields
    - Malformed individual rows (skipped with warning)
    - Unexpected values
    """

    # Expected header fields from TShark output
    EXPECTED_HEADERS = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "ip.proto",
        "_ws.col.Protocol",
        "frame.len",
        "tcp.stream",
        "tcp.flags",
        "ip.version",
        "frame.protocols",
    ]

    def __init__(self):
        """Initialize packet parser."""
        self._field_indices: dict[str, int] = {}

    def parse(self, tshark_result: TSharkResult) -> Iterator[PacketRecord]:
        """
        Parse TShark result into packet records.

        Args:
            tshark_result: Result from TSharkService.extract_packets()

        Yields:
            PacketRecord for each successfully parsed packet

        Note:
            Invalid rows are logged and skipped, not raised as errors.
            This allows partial processing of captures with some malformed data.
        """
        if tshark_result.status != TSharkStatus.SUCCESS:
            logger.warning(
                f"Cannot parse packets from unsuccessful TShark result: {tshark_result.status}"
            )
            return

        lines = tshark_result.stdout.strip().split('\n')
        if not lines:
            logger.info("No lines in TShark output")
            return

        # Parse header line to determine field positions
        header_line = lines[0]
        headers = header_line.split('\t')
        self._field_indices = {h: i for i, h in enumerate(headers)}

        # Log header mapping for debugging
        logger.debug(f"TShark output headers: {headers}")

        # Parse data lines
        packet_count = 0
        error_count = 0
        for line_num, line in enumerate(lines[1:], start=2):
            if not line.strip():
                continue

            try:
                record = self._parse_line(line)
                if record:
                    packet_count += 1
                    yield record
            except Exception as e:
                error_count += 1
                if error_count <= 10:  # Limit error logging
                    logger.warning(
                        f"Failed to parse packet at line {line_num}: {e}",
                        extra={"line_number": line_num}
                    )

        logger.info(
            f"Parsed {packet_count} packets from TShark output",
            extra={"packet_count": packet_count, "error_count": error_count}
        )

    def _parse_line(self, line: str) -> Optional[PacketRecord]:
        """
        Parse a single line of TShark output into a PacketRecord.

        Args:
            line: Tab-separated field values

        Returns:
            PacketRecord or None if line cannot be parsed
        """
        fields = line.split('\t')

        # Get frame number - this is required
        frame_num = self._get_field(fields, "frame.number")
        if frame_num is None:
            return None

        try:
            packet_number = int(frame_num)
        except ValueError:
            return None

        # Get IP addresses - prefer IPv4, fall back to IPv6
        src_ip = self._get_field(fields, "ip.src") or self._get_field(fields, "ipv6.src")
        dst_ip = self._get_field(fields, "ip.dst") or self._get_field(fields, "ipv6.dst")

        # Get ports - prefer TCP, fall back to UDP
        src_port = self._get_int_field(fields, "tcp.srcport") or self._get_int_field(fields, "udp.srcport")
        dst_port = self._get_int_field(fields, "tcp.dstport") or self._get_int_field(fields, "udp.dstport")

        # Determine transport protocol from IP protocol number
        ip_proto = self._get_int_field(fields, "ip.proto")
        transport_protocol = None
        if ip_proto == 6:
            transport_protocol = "TCP"
        elif ip_proto == 17:
            transport_protocol = "UDP"
        elif ip_proto == 1:
            transport_protocol = "ICMP"
        elif ip_proto == 58:
            transport_protocol = "ICMPv6"
        elif ip_proto is not None:
            transport_protocol = f"PROTO_{ip_proto}"

        return PacketRecord(
            packet_number=packet_number,
            timestamp=self._get_field(fields, "frame.time_epoch"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport_protocol=transport_protocol,
            detected_protocol=self._get_field(fields, "_ws.col.Protocol"),
            packet_length=self._get_int_field(fields, "frame.len"),
            tcp_stream=self._get_int_field(fields, "tcp.stream"),
            tcp_flags=self._get_field(fields, "tcp.flags"),
            ip_version=self._get_int_field(fields, "ip.version"),
            frame_protocols=self._get_field(fields, "frame.protocols"),
        )

    def _get_field(self, fields: list[str], field_name: str) -> Optional[str]:
        """Get a string field value, or None if not present/empty."""
        idx = self._field_indices.get(field_name)
        if idx is None or idx >= len(fields):
            return None
        value = fields[idx].strip()
        return value if value else None

    def _get_int_field(self, fields: list[str], field_name: str) -> Optional[int]:
        """Get an integer field value, or None if not present/empty/invalid."""
        value = self._get_field(fields, field_name)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    def count_packets(self, tshark_result: TSharkResult) -> int:
        """
        Count the number of packets in TShark output.

        This is faster than parsing all records when only count is needed.

        Args:
            tshark_result: Result from TSharkService

        Returns:
            Number of packet lines (excluding header)
        """
        if tshark_result.status != TSharkStatus.SUCCESS:
            return 0

        lines = tshark_result.stdout.strip().split('\n')
        if len(lines) <= 1:  # Only header or empty
            return 0

        # Count non-empty data lines
        return sum(1 for line in lines[1:] if line.strip())
