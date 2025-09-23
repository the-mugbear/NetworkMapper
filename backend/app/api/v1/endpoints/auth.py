"""
Authentication API Endpoints

Endpoints for user login, logout, registration, and session management.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.db.session import get_db
from app.db.models_auth import User, UserSession, UserRole
from app.core.security import (
    authenticate_user,
    create_access_token,
    verify_token,
    get_password_hash,
    validate_password_strength,
    log_audit_event,
    create_session,
    revoke_session,
    check_permissions
)

router = APIRouter()
security = HTTPBearer()


# Pydantic models for request/response
class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: Dict[str, Any]


class UserProfile(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    last_login: Optional[datetime]
    created_at: datetime


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def get_client_info(request: Request) -> Dict[str, Optional[str]]:
    """Extract client information from request"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent")
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token
    """
    token = credentials.credentials
    payload = verify_token(token)

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    # Check if session is still valid
    token_jti = payload.get("jti")
    session = db.query(UserSession).filter(
        UserSession.token_jti == token_jti,
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > datetime.utcnow()
    ).first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or revoked"
        )

    # Update last activity
    session.last_activity = datetime.utcnow()
    db.commit()

    return user


def require_role(required_role: str):
    """Decorator to require specific user role"""
    def role_checker(current_user: User = Depends(get_current_user)):
        if not check_permissions(current_user.role, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {required_role}"
            )
        return current_user
    return role_checker


@router.post("/login", response_model=LoginResponse)
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticate user and create session"""
    client_info = get_client_info(request)

    # Authenticate user
    user = authenticate_user(db, login_data.username, login_data.password)

    if not user:
        # Log failed login attempt
        log_audit_event(
            db=db,
            user_id=None,
            action="login_failed",
            details={"username": login_data.username},
            success=False,
            error_message="Invalid credentials",
            **client_info
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Create access token
    token_data = {"sub": str(user.id), "username": user.username, "role": user.role}
    access_token = create_access_token(data=token_data)

    # Decode token to get JTI for session tracking
    token_payload = verify_token(access_token)
    token_jti = token_payload["jti"]

    # Create session record
    create_session(
        db=db,
        user=user,
        token_jti=token_jti,
        **client_info
    )

    # Log successful login
    log_audit_event(
        db=db,
        user_id=user.id,
        action="login_success",
        details={"method": "password"},
        **client_info
    )

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=480 * 60,  # 8 hours in seconds
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    )


@router.post("/logout")
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Logout user and revoke session"""
    client_info = get_client_info(request)

    # Get token JTI for session revocation
    token = credentials.credentials
    payload = verify_token(token)
    token_jti = payload.get("jti")

    if token_jti:
        revoke_session(db, token_jti, "logout")

    # Log logout
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="logout",
        **client_info
    )

    return {"message": "Successfully logged out"}


@router.post("/register", response_model=UserProfile)
def register(
    registration_data: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Register new user (admin only)"""
    client_info = get_client_info(request)

    # Check if username already exists
    if db.query(User).filter(User.username == registration_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Check if email already exists
    if db.query(User).filter(User.email == registration_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Validate password strength
    password_validation = validate_password_strength(registration_data.password)
    if not password_validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
        )

    # Create new user
    hashed_password = get_password_hash(registration_data.password)
    new_user = User(
        username=registration_data.username,
        email=registration_data.email,
        hashed_password=hashed_password,
        full_name=registration_data.full_name,
        role=UserRole.VIEWER,  # Default role
        created_by_id=current_user.id
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log user creation
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="user_created",
        resource_type="user",
        resource_id=str(new_user.id),
        details={"new_username": new_user.username, "role": new_user.role},
        **client_info
    )

    return UserProfile(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        full_name=new_user.full_name,
        role=new_user.role,
        is_active=new_user.is_active,
        last_login=new_user.last_login,
        created_at=new_user.created_at
    )


@router.get("/profile", response_model=UserProfile)
def get_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    return UserProfile(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        last_login=current_user.last_login,
        created_at=current_user.created_at
    )


@router.post("/change-password")
def change_password(
    password_data: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    client_info = get_client_info(request)

    # Verify current password
    from app.core.security import verify_password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        log_audit_event(
            db=db,
            user_id=current_user.id,
            action="password_change_failed",
            success=False,
            error_message="Invalid current password",
            **client_info
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    # Validate new password strength
    password_validation = validate_password_strength(password_data.new_password)
    if not password_validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
        )

    # Update password
    current_user.hashed_password = get_password_hash(password_data.new_password)
    current_user.password_changed_at = datetime.utcnow()
    db.commit()

    # Log password change
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="password_changed",
        **client_info
    )

    return {"message": "Password successfully changed"}


@router.get("/sessions")
def get_active_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's active sessions"""
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > datetime.utcnow()
    ).all()

    return [
        {
            "id": session.id,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "expires_at": session.expires_at
        }
        for session in sessions
    ]


@router.delete("/sessions/{session_id}")
def revoke_session_endpoint(
    session_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a specific session"""
    client_info = get_client_info(request)

    session = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == current_user.id
    ).first()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    revoke_session(db, session.token_jti, "manual_revocation")

    # Log session revocation
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="session_revoked",
        resource_type="session",
        resource_id=str(session_id),
        **client_info
    )

    return {"message": "Session revoked successfully"}