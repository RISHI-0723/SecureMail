"""API dependencies for authentication and authorization - Phase 5.

Provides FastAPI dependencies for:
- JWT token validation
- Current user extraction
- Role-based authorization
- Rate limiting
- Request tracking
"""
import logging
import uuid
from typing import Optional, List
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token
from app.core.config import settings
from app.models.user import User, UserRole, UserStatus, AuditLog

logger = logging.getLogger(__name__)

# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)


def get_request_id(request: Request) -> str:
    """
    Get or generate request ID for tracking.

    Args:
        request: FastAPI request object

    Returns:
        Request ID string
    """
    request_id = request.headers.get("X-Request-ID")
    if not request_id:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
    return request_id


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get current user from JWT token (optional).

    Returns None if no valid token provided.
    Does not raise exception for missing/invalid token.

    Args:
        request: FastAPI request object
        credentials: HTTP authorization credentials
        db: Database session

    Returns:
        User object or None
    """
    if not credentials:
        return None

    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        return None

    # Check token type
    if payload.get("type") != "access":
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    # Get user from database
    user = db.query(User).filter(User.user_id == user_id).first()

    if not user:
        return None

    # Check user status
    if user.status != UserStatus.ACTIVE:
        return None

    return user


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token.

    Raises HTTPException if authentication fails.

    Args:
        request: FastAPI request object
        credentials: HTTP authorization credentials
        db: Database session

    Returns:
        Authenticated User object

    Raises:
        HTTPException: If authentication fails
    """
    request_id = get_request_id(request)

    if not credentials:
        logger.warning(
            "Missing authentication token",
            extra={"request_id": request_id}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_REQUIRED",
                "message": "Authentication token required",
                "request_id": request_id
            },
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        logger.warning(
            "Invalid authentication token",
            extra={"request_id": request_id}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_TOKEN",
                "message": "Invalid or expired authentication token",
                "request_id": request_id
            },
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check token type
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_TOKEN_TYPE",
                "message": "Invalid token type",
                "request_id": request_id
            },
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_TOKEN",
                "message": "Token missing user identifier",
                "request_id": request_id
            },
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Get user from database
    user = db.query(User).filter(User.user_id == user_id).first()

    if not user:
        logger.warning(
            f"User not found for token",
            extra={"request_id": request_id, "user_id": user_id}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "USER_NOT_FOUND",
                "message": "User account not found",
                "request_id": request_id
            },
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check user status
    if user.status == UserStatus.LOCKED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ACCOUNT_LOCKED",
                "message": "Account is locked",
                "request_id": request_id
            }
        )

    if user.status == UserStatus.INACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ACCOUNT_INACTIVE",
                "message": "Account is inactive",
                "request_id": request_id
            }
        )

    return user


def require_roles(allowed_roles: List[UserRole]):
    """
    Create a dependency that requires specific user roles.

    Args:
        allowed_roles: List of allowed roles

    Returns:
        Dependency function that validates user role
    """
    async def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user)
    ) -> User:
        request_id = get_request_id(request)

        if current_user.role not in allowed_roles:
            logger.warning(
                f"Access denied: insufficient role",
                extra={
                    "request_id": request_id,
                    "user_id": current_user.user_id,
                    "user_role": current_user.role.value,
                    "required_roles": [r.value for r in allowed_roles]
                }
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "INSUFFICIENT_PERMISSIONS",
                    "message": "You do not have permission to perform this action",
                    "request_id": request_id
                }
            )

        return current_user

    return role_checker


# Pre-built role dependencies
require_admin = require_roles([UserRole.ADMIN])
require_analyst = require_roles([UserRole.ADMIN, UserRole.ANALYST])
require_viewer = require_roles([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])


def log_audit_event(
    db: Session,
    action: str,
    user: Optional[User] = None,
    request: Optional[Request] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    status: str = "SUCCESS",
    details: Optional[str] = None
) -> None:
    """
    Log an audit event.

    Args:
        db: Database session
        action: Action performed
        user: User who performed the action
        request: Request object for IP/UA
        resource_type: Type of resource affected
        resource_id: ID of resource affected
        status: SUCCESS or FAILURE
        details: Additional details
    """
    try:
        audit_log = AuditLog(
            action=action,
            user_id=user.user_id if user else None,
            username=user.username if user else None,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("User-Agent") if request else None,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            details=details,
            request_id=get_request_id(request) if request else None
        )
        db.add(audit_log)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")
        db.rollback()


def get_user_permissions(user: User) -> List[str]:
    """
    Get list of permissions for a user based on role.

    Args:
        user: User object

    Returns:
        List of permission strings
    """
    permissions = []

    # All users can read
    permissions.extend([
        "cases:read",
        "evidence:read",
        "analysis:read",
        "findings:read",
        "reports:read"
    ])

    # Analysts can create and modify
    if user.role in [UserRole.ADMIN, UserRole.ANALYST]:
        permissions.extend([
            "cases:create",
            "cases:update",
            "evidence:upload",
            "analysis:create",
            "reports:generate"
        ])

    # Admins have full access
    if user.role == UserRole.ADMIN:
        permissions.extend([
            "cases:delete",
            "evidence:delete",
            "users:read",
            "users:create",
            "users:update",
            "users:delete",
            "admin:access"
        ])

    return permissions
