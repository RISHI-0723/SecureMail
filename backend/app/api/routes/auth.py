"""Authentication routes - Phase 5.

Endpoints for:
- User login
- Token refresh
- Current user info
- Password change
- User management (admin)
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.database import get_db
from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_password_strength
)
from app.models.user import User, UserRole, UserStatus
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
    PasswordChange,
    MeResponse
)
from app.api.dependencies import (
    get_current_user,
    require_admin,
    get_request_id,
    log_audit_event,
    get_user_permissions
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    request: Request,
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """
    Register a new user account.

    Public endpoint - does not require authentication.
    After successful registration, user is automatically logged in.

    Args:
        request: FastAPI request
        user_data: User registration data
        db: Database session

    Returns:
        JWT access and refresh tokens

    Raises:
        HTTPException: On registration failure
    """
    request_id = get_request_id(request)

    # Check for existing username
    existing_user = db.query(User).filter(
        or_(
            User.username == user_data.username,
            User.email == user_data.email
        )
    ).first()

    if existing_user:
        if existing_user.username == user_data.username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "USERNAME_EXISTS",
                    "message": "Username already exists",
                    "request_id": request_id
                }
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "EMAIL_EXISTS",
                    "message": "Email already exists",
                    "request_id": request_id
                }
            )

    # Validate password strength
    is_valid, error_msg = validate_password_strength(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "WEAK_PASSWORD",
                "message": error_msg,
                "request_id": request_id
            }
        )

    # Create new user with VIEWER role (safe default)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=UserRole.VIEWER,  # New users get VIEWER role for security
        status=UserStatus.ACTIVE
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        logger.info(
            "New user registered",
            extra={"request_id": request_id, "user_id": new_user.user_id, "username": new_user.username}
        )
        log_audit_event(
            db,
            action="USER_SIGNUP",
            user=new_user,
            request=request
        )

        # Auto-login: create tokens
        token_data = {
            "sub": new_user.user_id,
            "username": new_user.username,
            "role": new_user.role.value
        }

        access_token = create_access_token(token_data)
        refresh_token_str = create_refresh_token(token_data)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60
        )

    except Exception as e:
        db.rollback()
        logger.error(f"User registration failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "REGISTRATION_FAILED",
                "message": "Failed to create user account",
                "request_id": request_id
            }
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens.

    Args:
        request: FastAPI request
        login_data: Login credentials
        db: Database session

    Returns:
        JWT access and refresh tokens

    Raises:
        HTTPException: On authentication failure
    """
    request_id = get_request_id(request)

    # Find user by username or email
    user = db.query(User).filter(
        or_(
            User.username == login_data.username,
            User.email == login_data.username
        )
    ).first()

    # User not found
    if not user:
        logger.warning(
            "Login failed: user not found",
            extra={"request_id": request_id, "username": login_data.username}
        )
        log_audit_event(
            db,
            action="LOGIN_FAILED",
            request=request,
            details=f"User not found: {login_data.username}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_CREDENTIALS",
                "message": "Invalid username or password",
                "request_id": request_id
            }
        )

    # Check if account is locked
    if user.is_locked(max_attempts=5):
        logger.warning(
            "Login failed: account locked",
            extra={"request_id": request_id, "user_id": user.user_id}
        )
        log_audit_event(
            db,
            action="LOGIN_BLOCKED",
            user=user,
            request=request,
            status="FAILURE",
            details="Account locked due to too many failed attempts"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ACCOUNT_LOCKED",
                "message": "Account is locked due to too many failed login attempts",
                "request_id": request_id
            }
        )

    # Check account status
    if user.status == UserStatus.INACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ACCOUNT_INACTIVE",
                "message": "Account is inactive",
                "request_id": request_id
            }
        )

    # Verify password
    if not verify_password(login_data.password, user.password_hash):
        failed_attempts = user.increment_failed_attempts()
        db.commit()

        logger.warning(
            f"Login failed: invalid password (attempt {failed_attempts})",
            extra={"request_id": request_id, "user_id": user.user_id}
        )
        log_audit_event(
            db,
            action="LOGIN_FAILED",
            user=user,
            request=request,
            status="FAILURE",
            details=f"Invalid password (attempt {failed_attempts})"
        )

        # Lock account after 5 failed attempts
        if failed_attempts >= 5:
            user.status = UserStatus.LOCKED
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_CREDENTIALS",
                "message": "Invalid username or password",
                "request_id": request_id
            }
        )

    # Successful login
    user.reset_failed_attempts()
    db.commit()

    # Create tokens
    token_data = {
        "sub": user.user_id,
        "username": user.username,
        "role": user.role.value
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    logger.info(
        "User logged in successfully",
        extra={"request_id": request_id, "user_id": user.user_id}
    )
    log_audit_event(
        db,
        action="LOGIN_SUCCESS",
        user=user,
        request=request
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using refresh token.

    Args:
        request: FastAPI request
        refresh_data: Refresh token
        db: Database session

    Returns:
        New JWT access and refresh tokens
    """
    request_id = get_request_id(request)

    payload = decode_token(refresh_data.refresh_token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_TOKEN",
                "message": "Invalid or expired refresh token",
                "request_id": request_id
            }
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_TOKEN_TYPE",
                "message": "Invalid token type",
                "request_id": request_id
            }
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.user_id == user_id).first()

    if not user or user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "USER_NOT_FOUND",
                "message": "User account not found or inactive",
                "request_id": request_id
            }
        )

    # Create new tokens
    token_data = {
        "sub": user.user_id,
        "username": user.username,
        "role": user.role.value
    }

    access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token(token_data)

    log_audit_event(
        db,
        action="TOKEN_REFRESH",
        user=user,
        request=request
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.get("/me", response_model=MeResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current authenticated user information.

    Args:
        current_user: Current authenticated user

    Returns:
        User info with permissions
    """
    permissions = get_user_permissions(current_user)

    return MeResponse(
        user_id=current_user.user_id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role.value,
        permissions=permissions
    )


@router.post("/change-password")
async def change_password(
    request: Request,
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change current user's password.

    Args:
        request: FastAPI request
        password_data: Current and new passwords
        current_user: Current authenticated user
        db: Database session
    """
    request_id = get_request_id(request)

    # Verify current password
    if not verify_password(password_data.current_password, current_user.password_hash):
        log_audit_event(
            db,
            action="PASSWORD_CHANGE_FAILED",
            user=current_user,
            request=request,
            status="FAILURE",
            details="Invalid current password"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "INVALID_PASSWORD",
                "message": "Current password is incorrect",
                "request_id": request_id
            }
        )

    # Validate new password strength
    is_valid, error_msg = validate_password_strength(password_data.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "WEAK_PASSWORD",
                "message": error_msg,
                "request_id": request_id
            }
        )

    # Update password
    current_user.password_hash = hash_password(password_data.new_password)
    current_user.password_changed_at = datetime.now(timezone.utc)
    db.commit()

    log_audit_event(
        db,
        action="PASSWORD_CHANGED",
        user=current_user,
        request=request
    )

    return {"message": "Password changed successfully"}


# =========================================================================
# Admin User Management Endpoints
# =========================================================================

@router.get("/users", response_model=UserListResponse)
async def list_users(
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    List all users (admin only).

    Args:
        skip: Number of records to skip
        limit: Maximum records to return
        current_user: Current admin user
        db: Database session

    Returns:
        List of users
    """
    # Validate pagination
    limit = min(limit, 100)

    users = db.query(User).offset(skip).limit(limit).all()
    total = db.query(User).count()

    return UserListResponse(
        users=[UserResponse.model_validate(u) for u in users],
        total=total
    )


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    user_data: UserCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Create a new user (admin only).

    Args:
        request: FastAPI request
        user_data: User creation data
        current_user: Current admin user
        db: Database session

    Returns:
        Created user
    """
    request_id = get_request_id(request)

    # Check for existing username
    existing = db.query(User).filter(
        or_(
            User.username == user_data.username,
            User.email == user_data.email
        )
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "USER_EXISTS",
                "message": "Username or email already exists",
                "request_id": request_id
            }
        )

    # Validate password strength
    is_valid, error_msg = validate_password_strength(user_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "WEAK_PASSWORD",
                "message": error_msg,
                "request_id": request_id
            }
        )

    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=UserRole(user_data.role),
        created_by=current_user.user_id
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db,
        action="USER_CREATED",
        user=current_user,
        request=request,
        resource_type="user",
        resource_id=user.user_id,
        details=f"Created user: {user.username}"
    )

    return UserResponse.model_validate(user)


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get a user by ID (admin only).

    Args:
        user_id: User ID to retrieve
        current_user: Current admin user
        db: Database session

    Returns:
        User details
    """
    user = db.query(User).filter(User.user_id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": "User not found"
            }
        )

    return UserResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: str,
    user_data: UserUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Update a user (admin only).

    Args:
        request: FastAPI request
        user_id: User ID to update
        user_data: Update data
        current_user: Current admin user
        db: Database session

    Returns:
        Updated user
    """
    user = db.query(User).filter(User.user_id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": "User not found"
            }
        )

    # Update fields
    update_data = user_data.model_dump(exclude_unset=True)

    if "email" in update_data:
        # Check for existing email
        existing = db.query(User).filter(
            User.email == update_data["email"],
            User.user_id != user_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "EMAIL_EXISTS",
                    "message": "Email already in use"
                }
            )
        user.email = update_data["email"]

    if "full_name" in update_data:
        user.full_name = update_data["full_name"]

    if "role" in update_data:
        user.role = UserRole(update_data["role"])

    if "status" in update_data:
        user.status = UserStatus(update_data["status"])
        if update_data["status"] == "ACTIVE":
            user.failed_login_attempts = "0"

    db.commit()
    db.refresh(user)

    log_audit_event(
        db,
        action="USER_UPDATED",
        user=current_user,
        request=request,
        resource_type="user",
        resource_id=user.user_id,
        details=f"Updated fields: {list(update_data.keys())}"
    )

    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    request: Request,
    user_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete a user (admin only).

    Args:
        request: FastAPI request
        user_id: User ID to delete
        current_user: Current admin user
        db: Database session
    """
    if user_id == current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "CANNOT_DELETE_SELF",
                "message": "Cannot delete your own account"
            }
        )

    user = db.query(User).filter(User.user_id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": "User not found"
            }
        )

    username = user.username
    db.delete(user)
    db.commit()

    log_audit_event(
        db,
        action="USER_DELETED",
        user=current_user,
        request=request,
        resource_type="user",
        resource_id=user_id,
        details=f"Deleted user: {username}"
    )

    return None
