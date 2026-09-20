"""Pytest configuration and fixtures."""
import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db

# Import all models to ensure they're registered with Base
from app.models import (
    Case, CaseStatus,
    PcapEvidence, EvidenceStatus, FileFormat,
    AnalysisJob, JobStatus, JobType,
    PacketAnalysis,
)


# Create test database in memory
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def test_db():
    """Create a fresh test database for each test."""
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Enable foreign keys for SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    """Create test client with database override."""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def temp_storage_path():
    """Create a temporary directory for evidence storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def valid_pcap_bytes():
    """Valid PCAP file header (little-endian)."""
    # PCAP header: magic (4) + version (4) + timezone (4) + sigfigs (4) + snaplen (4) + network (4) = 24 bytes
    return bytes([
        0xd4, 0xc3, 0xb2, 0xa1,  # Magic number (little-endian)
        0x02, 0x00, 0x04, 0x00,  # Version 2.4
        0x00, 0x00, 0x00, 0x00,  # Timezone (GMT)
        0x00, 0x00, 0x00, 0x00,  # Sigfigs
        0xff, 0xff, 0x00, 0x00,  # Snaplen (65535)
        0x01, 0x00, 0x00, 0x00,  # Network (Ethernet)
    ])


@pytest.fixture
def valid_pcap_be_bytes():
    """Valid PCAP file header (big-endian)."""
    return bytes([
        0xa1, 0xb2, 0xc3, 0xd4,  # Magic number (big-endian)
        0x00, 0x02, 0x00, 0x04,  # Version 2.4
        0x00, 0x00, 0x00, 0x00,  # Timezone (GMT)
        0x00, 0x00, 0x00, 0x00,  # Sigfigs
        0x00, 0x00, 0xff, 0xff,  # Snaplen (65535)
        0x00, 0x00, 0x00, 0x01,  # Network (Ethernet)
    ])


@pytest.fixture
def valid_pcapng_bytes():
    """Valid PCAPNG file header (Section Header Block)."""
    # PCAPNG Section Header Block
    return bytes([
        0x0a, 0x0d, 0x0d, 0x0a,  # Block Type (Section Header)
        0x1c, 0x00, 0x00, 0x00,  # Block Total Length (28)
        0x4d, 0x3c, 0x2b, 0x1a,  # Byte Order Magic
        0x01, 0x00, 0x00, 0x00,  # Version 1.0
        0xff, 0xff, 0xff, 0xff,  # Section Length
        0xff, 0xff, 0xff, 0xff,  # Section Length (high)
        0x1c, 0x00, 0x00, 0x00,  # Block Total Length (repeated)
    ])


@pytest.fixture
def invalid_file_bytes():
    """Invalid file content (not PCAP/PCAPNG)."""
    return b"This is not a valid PCAP file content!"


@pytest.fixture
def text_file_bytes():
    """Plain text file content."""
    return b"Hello World\nThis is a text file."


@pytest.fixture
def jpg_file_bytes():
    """JPEG file header."""
    return bytes([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46])


# =============================================================================
# PHASE 2 FIXTURES
# =============================================================================

@pytest.fixture
def mock_tshark_smtp_output():
    """Mock TShark output with SMTP traffic."""
    header = (
        "frame.number\tframe.time_epoch\tip.src\tip.dst\tipv6.src\tipv6.dst\t"
        "tcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tip.proto\t"
        "_ws.col.Protocol\tframe.len\ttcp.stream\ttcp.flags\tip.version\tframe.protocols"
    )
    packets = [
        "1\t1234567890.123\t192.168.1.1\t192.168.1.2\t\t\t12345\t25\t\t\t6\tSMTP\t100\t0\t0x018\t4\teth:ip:tcp:smtp",
        "2\t1234567890.456\t192.168.1.2\t192.168.1.1\t\t\t25\t12345\t\t\t6\tSMTP\t150\t0\t0x010\t4\teth:ip:tcp:smtp",
        "3\t1234567890.789\t192.168.1.1\t192.168.1.2\t\t\t12345\t25\t\t\t6\tSMTP\t200\t0\t0x018\t4\teth:ip:tcp:smtp",
    ]
    return header + "\n" + "\n".join(packets)


@pytest.fixture
def mock_tshark_mixed_protocols_output():
    """Mock TShark output with multiple email protocols."""
    header = (
        "frame.number\tframe.time_epoch\tip.src\tip.dst\tipv6.src\tipv6.dst\t"
        "tcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tip.proto\t"
        "_ws.col.Protocol\tframe.len\ttcp.stream\ttcp.flags\tip.version\tframe.protocols"
    )
    packets = [
        "1\t1234567890.123\t192.168.1.1\t192.168.1.2\t\t\t12345\t25\t\t\t6\tSMTP\t100\t0\t0x018\t4\teth:ip:tcp:smtp",
        "2\t1234567890.200\t192.168.1.1\t192.168.1.3\t\t\t23456\t143\t\t\t6\tIMAP\t120\t1\t0x018\t4\teth:ip:tcp:imap",
        "3\t1234567890.300\t192.168.1.1\t192.168.1.4\t\t\t34567\t110\t\t\t6\tPOP\t80\t2\t0x018\t4\teth:ip:tcp:pop",
        "4\t1234567890.400\t192.168.1.1\t192.168.1.5\t\t\t45678\t443\t\t\t6\tTLSv1.2\t500\t3\t0x018\t4\teth:ip:tcp:tls",
    ]
    return header + "\n" + "\n".join(packets)


@pytest.fixture
def mock_tshark_http_only_output():
    """Mock TShark output with only HTTP traffic (no email)."""
    header = (
        "frame.number\tframe.time_epoch\tip.src\tip.dst\tipv6.src\tipv6.dst\t"
        "tcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tip.proto\t"
        "_ws.col.Protocol\tframe.len\ttcp.stream\ttcp.flags\tip.version\tframe.protocols"
    )
    packets = [
        "1\t1234567890.123\t192.168.1.1\t192.168.1.2\t\t\t12345\t80\t\t\t6\tHTTP\t500\t0\t0x018\t4\teth:ip:tcp:http",
        "2\t1234567890.456\t192.168.1.2\t192.168.1.1\t\t\t80\t12345\t\t\t6\tHTTP\t1500\t0\t0x010\t4\teth:ip:tcp:http",
    ]
    return header + "\n" + "\n".join(packets)


@pytest.fixture
def mock_tshark_empty_output():
    """Mock TShark output with empty capture."""
    header = (
        "frame.number\tframe.time_epoch\tip.src\tip.dst\tipv6.src\tipv6.dst\t"
        "tcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tip.proto\t"
        "_ws.col.Protocol\tframe.len\ttcp.stream\ttcp.flags\tip.version\tframe.protocols"
    )
    return header
