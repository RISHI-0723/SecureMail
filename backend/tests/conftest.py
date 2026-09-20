"""Pytest configuration and fixtures."""
import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db


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
