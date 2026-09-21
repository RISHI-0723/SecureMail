"""User model for authentication - Phase 5.

Implements secure user management with:
- Password hashing (Argon2id via passlib)
- Role-based access control
- Audit fields
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Boolean, DateTime, Enum,
    Index, Text
)
from sqlalchemy.orm import relationship
from app.core.database import Base


class UserRole(str, PyEnum):
    """User roles for authorization."""
    ADMIN = "ADMIN"         # Full system access
    ANALYST = "ANALYST"     # Can create cases, analyze evidence
    VIEWER = "VIEWER"       # Read-only access to assigned cases


class UserStatus(str, PyEnum):
    """User account status."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    LOCKED = "LOCKED"       # Too many failed login attempts


def generate_user_id() -> str:
    """Generate a unique user ID."""
    return f"user_{uuid.uuid4().hex[:12]}"


class User(Base):
    """
    User entity for authentication and authorization.

    Security features:
    - Password is hashed, never stored in plaintext
    - Failed login attempts tracked for lockout
    - Audit trail for account changes
    """
    __tablename__ = "users"

    user_id = Column(
        String(50),
        primary_key=True,
        default=generate_user_id,
        index=True
    )
    username = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )
    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    password_hash = Column(
        String(255),
        nullable=False
    )
    role = Column(
        Enum(UserRole),
        nullable=False,
        default=UserRole.VIEWER
    )
    status = Column(
        Enum(UserStatus),
        nullable=False,
        default=UserStatus.ACTIVE,
        index=True
    )

    # Profile
    full_name = Column(String(255), nullable=True)

    # Security tracking
    failed_login_attempts = Column(
        String(10),
        nullable=False,
        default="0"
    )
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_failed_login = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)

    # Audit fields
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=lambda: datetime.now(timezone.utc)
    )
    created_by = Column(String(50), nullable=True)

    # Indexes for common queries
    __table_args__ = (
        Index("ix_users_role_status", "role", "status"),
    )

    def __repr__(self) -> str:
        return f"<User(user_id={self.user_id}, username={self.username}, role={self.role})>"

    @property
    def failed_attempts(self) -> int:
        """Get failed login attempts as integer."""
        try:
            return int(self.failed_login_attempts)
        except (ValueError, TypeError):
            return 0

    def increment_failed_attempts(self) -> int:
        """Increment and return failed login attempts."""
        current = self.failed_attempts
        self.failed_login_attempts = str(current + 1)
        self.last_failed_login = datetime.now(timezone.utc)
        return current + 1

    def reset_failed_attempts(self) -> None:
        """Reset failed login attempts after successful login."""
        self.failed_login_attempts = "0"
        self.last_login = datetime.now(timezone.utc)

    def is_locked(self, max_attempts: int = 5) -> bool:
        """Check if account is locked due to failed attempts."""
        if self.status == UserStatus.LOCKED:
            return True
        return self.failed_attempts >= max_attempts


class AuditLog(Base):
    """
    Audit log for security-relevant events.

    Tracks:
    - Authentication events (login, logout, failed attempts)
    - Authorization events (access denied)
    - Data access (evidence access, report generation)
    - Administrative actions
    """
    __tablename__ = "audit_logs"

    log_id = Column(
        String(50),
        primary_key=True,
        default=lambda: f"audit_{uuid.uuid4().hex[:12]}",
        index=True
    )
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    # Who
    user_id = Column(String(50), nullable=True, index=True)
    username = Column(String(50), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    user_agent = Column(Text, nullable=True)

    # What
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)

    # Details
    status = Column(String(20), nullable=False, default="SUCCESS")
    details = Column(Text, nullable=True)
    request_id = Column(String(50), nullable=True, index=True)

    # Indexes for audit queries
    __table_args__ = (
        Index("ix_audit_user_action", "user_id", "action"),
        Index("ix_audit_timestamp_action", "timestamp", "action"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(log_id={self.log_id}, action={self.action}, user_id={self.user_id})>"
