"""TShark service abstraction for secure packet analysis.

This service provides safe TShark execution with:
- Binary validation before analysis
- Timeout handling
- Structured error capture
- No shell=True usage
- Proper process termination
"""
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.services.packet.models import TSharkStatus, TSharkResult

logger = logging.getLogger(__name__)


class TSharkError(Exception):
    """Exception raised for TShark-related errors."""
    def __init__(self, message: str, code: str, stderr: str = ""):
        self.message = message
        self.code = code
        self.stderr = stderr
        super().__init__(message)


class TSharkService:
    """
    Service for executing TShark commands safely.

    Features:
    - Binary validation before analysis
    - Configurable timeout
    - Structured output capture
    - Process termination handling
    - No shell injection vulnerabilities
    """

    # TShark output fields for packet extraction
    # Using -T fields with -e options for structured output
    PACKET_FIELDS = [
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

    def __init__(
        self,
        binary_path: Optional[str] = None,
        timeout_seconds: Optional[int] = None
    ):
        """
        Initialize TShark service.

        Args:
            binary_path: Path to TShark binary. Defaults to settings.
            timeout_seconds: Execution timeout. Defaults to settings.
        """
        self.binary_path = binary_path or settings.tshark_binary
        self.timeout_seconds = timeout_seconds or settings.tshark_timeout_seconds
        self._validated_binary: Optional[str] = None
        self._tshark_version: Optional[str] = None

    def validate_binary(self) -> tuple[bool, str]:
        """
        Validate that the TShark binary exists and is executable.

        This MUST be called before any analysis. If validation fails,
        analysis should not proceed.

        Returns:
            Tuple of (is_valid, resolved_path_or_error_message)
        """
        # If already validated in this service instance, return cached result
        if self._validated_binary:
            return True, self._validated_binary

        binary = self.binary_path

        # If it's a command name (not a path), try to resolve it
        if not os.path.sep in binary and not (os.name == 'nt' and '\\' in binary):
            # Use shutil.which to find the binary in PATH
            resolved = shutil.which(binary)
            if resolved:
                binary = resolved
            else:
                logger.error(f"TShark binary not found in PATH: {self.binary_path}")
                return False, f"TShark binary not found: {self.binary_path}"

        # Validate the path
        path = Path(binary)

        if not path.exists():
            logger.error(f"TShark binary does not exist: {binary}")
            return False, f"TShark binary not found: {binary}"

        if not path.is_file():
            logger.error(f"TShark path is not a file: {binary}")
            return False, f"TShark path is not a file: {binary}"

        if not os.access(binary, os.X_OK):
            logger.error(f"TShark binary is not executable: {binary}")
            return False, f"TShark binary is not executable: {binary}"

        self._validated_binary = str(path.resolve())
        logger.info(f"TShark binary validated: {self._validated_binary}")
        return True, self._validated_binary

    def get_version(self) -> Optional[str]:
        """
        Get the TShark version.

        Returns:
            Version string or None if cannot be determined
        """
        if self._tshark_version:
            return self._tshark_version

        is_valid, binary_or_error = self.validate_binary()
        if not is_valid:
            return None

        try:
            result = subprocess.run(
                [self._validated_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Parse version from first line, e.g., "TShark (Wireshark) 4.0.6"
                first_line = result.stdout.split('\n')[0] if result.stdout else ""
                if "TShark" in first_line:
                    # Extract version number
                    parts = first_line.split()
                    for i, part in enumerate(parts):
                        if part.startswith("(") and i + 1 < len(parts):
                            # Next part after (Wireshark) is version
                            continue
                        if part[0].isdigit():
                            self._tshark_version = part.rstrip(",")
                            break
                    if not self._tshark_version:
                        self._tshark_version = first_line
                    return self._tshark_version
        except Exception as e:
            logger.warning(f"Could not get TShark version: {e}")

        return None

    def extract_packets(self, evidence_path: str) -> TSharkResult:
        """
        Extract packet metadata from a PCAP/PCAPNG file.

        Args:
            evidence_path: Path to the evidence file

        Returns:
            TSharkResult with extraction outcome

        Note:
            This method validates the TShark binary before execution.
            If validation fails, it returns immediately with NOT_FOUND status.
        """
        start_time = time.time()

        # Step 1: Validate TShark binary BEFORE loading evidence
        is_valid, binary_or_error = self.validate_binary()
        if not is_valid:
            return TSharkResult(
                status=TSharkStatus.NOT_FOUND,
                exit_code=None,
                stdout="",
                stderr=binary_or_error,
                timed_out=False,
                duration_seconds=time.time() - start_time
            )

        # Step 2: Validate evidence file exists
        evidence = Path(evidence_path)
        if not evidence.exists():
            return TSharkResult(
                status=TSharkStatus.FAILED,
                exit_code=None,
                stdout="",
                stderr=f"Evidence file not found: {evidence_path}",
                timed_out=False,
                duration_seconds=time.time() - start_time
            )

        if not evidence.is_file():
            return TSharkResult(
                status=TSharkStatus.FAILED,
                exit_code=None,
                stdout="",
                stderr=f"Evidence path is not a file: {evidence_path}",
                timed_out=False,
                duration_seconds=time.time() - start_time
            )

        # Step 3: Build TShark command
        # Using -T fields with -e options for structured, machine-parseable output
        # -E header=y includes field names as header
        # -E separator=\t uses tab as field separator
        cmd = [
            self._validated_binary,
            "-n",
            "-r", str(evidence),
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=\t",
            "-E", "quote=n",
            "-E", "occurrence=f",
        ]

        # Add field extraction options
        for field in self.PACKET_FIELDS:
            cmd.extend(["-e", field])

        logger.info(
            f"Executing TShark for evidence: {evidence_path}",
            extra={"evidence_path": evidence_path, "timeout": self.timeout_seconds}
        )

        # Step 4: Execute TShark with timeout
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
                duration = time.time() - start_time

                if process.returncode == 0:
                    logger.info(
                        f"TShark completed successfully in {duration:.2f}s",
                        extra={
                            "evidence_path": evidence_path,
                            "duration_seconds": duration,
                            "exit_code": 0
                        }
                    )
                    return TSharkResult(
                        status=TSharkStatus.SUCCESS,
                        exit_code=0,
                        stdout=stdout,
                        stderr=stderr,
                        timed_out=False,
                        duration_seconds=duration,
                        tshark_version=self.get_version()
                    )
                else:
                    logger.error(
                        f"TShark failed with exit code {process.returncode}",
                        extra={
                            "evidence_path": evidence_path,
                            "exit_code": process.returncode,
                            "stderr": stderr[:500] if stderr else ""
                        }
                    )
                    return TSharkResult(
                        status=TSharkStatus.FAILED,
                        exit_code=process.returncode,
                        stdout=stdout,
                        stderr=stderr,
                        timed_out=False,
                        duration_seconds=duration,
                        tshark_version=self.get_version()
                    )

            except subprocess.TimeoutExpired:
                # Kill the process
                process.kill()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    stdout, stderr = "", "Process did not terminate after kill"
                    process.terminate()

                duration = time.time() - start_time
                logger.error(
                    f"TShark timed out after {self.timeout_seconds}s",
                    extra={
                        "evidence_path": evidence_path,
                        "timeout_seconds": self.timeout_seconds,
                        "duration_seconds": duration
                    }
                )
                return TSharkResult(
                    status=TSharkStatus.TIMEOUT,
                    exit_code=None,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    timed_out=True,
                    duration_seconds=duration,
                    tshark_version=self.get_version()
                )

        except FileNotFoundError:
            # Binary disappeared after validation (very unlikely)
            duration = time.time() - start_time
            return TSharkResult(
                status=TSharkStatus.NOT_FOUND,
                exit_code=None,
                stdout="",
                stderr=f"TShark binary not found during execution: {self._validated_binary}",
                timed_out=False,
                duration_seconds=duration
            )
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"TShark execution error: {e}")
            return TSharkResult(
                status=TSharkStatus.FAILED,
                exit_code=None,
                stdout="",
                stderr=str(e),
                timed_out=False,
                duration_seconds=duration
            )

    def count_packets(self, evidence_path: str) -> TSharkResult:
        """
        Count total packets in a PCAP/PCAPNG file.

        This is a lightweight operation for getting total packet count.

        Args:
            evidence_path: Path to the evidence file

        Returns:
            TSharkResult with packet count in stdout
        """
        start_time = time.time()

        is_valid, binary_or_error = self.validate_binary()
        if not is_valid:
            return TSharkResult(
                status=TSharkStatus.NOT_FOUND,
                exit_code=None,
                stdout="",
                stderr=binary_or_error,
                timed_out=False,
                duration_seconds=time.time() - start_time
            )

        evidence = Path(evidence_path)
        if not evidence.exists() or not evidence.is_file():
            return TSharkResult(
                status=TSharkStatus.FAILED,
                exit_code=None,
                stdout="",
                stderr=f"Evidence file not found: {evidence_path}",
                timed_out=False,
                duration_seconds=time.time() - start_time
            )

        # Use -c 0 to count all packets (statistics mode)
        cmd = [
            self._validated_binary,
            "-r", str(evidence),
            "-T", "fields",
            "-e", "frame.number"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds
            )
            duration = time.time() - start_time

            if result.returncode == 0:
                return TSharkResult(
                    status=TSharkStatus.SUCCESS,
                    exit_code=0,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    timed_out=False,
                    duration_seconds=duration,
                    tshark_version=self.get_version()
                )
            else:
                return TSharkResult(
                    status=TSharkStatus.FAILED,
                    exit_code=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    timed_out=False,
                    duration_seconds=duration
                )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return TSharkResult(
                status=TSharkStatus.TIMEOUT,
                exit_code=None,
                stdout="",
                stderr="Packet counting timed out",
                timed_out=True,
                duration_seconds=duration
            )
        except Exception as e:
            duration = time.time() - start_time
            return TSharkResult(
                status=TSharkStatus.FAILED,
                exit_code=None,
                stdout="",
                stderr=str(e),
                timed_out=False,
                duration_seconds=duration
            )


# Global TShark service instance
tshark_service = TSharkService()
