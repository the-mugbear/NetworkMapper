"""
Security utilities for authentication and authorization
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
import bcrypt
import secrets
import hashlib
from passlib.context import CryptContext
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models_auth import User, UserSession, AuditLog, UserRole

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = getattr(settings, 'SECRET_KEY', secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 480)  # 8 hours


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password meets security requirements

    Returns:
        Dict with 'valid' boolean and 'errors' list
    """
    errors = []

    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")

    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")

    return {
        "valid": len(errors) == 0,
        "errors": errors
    }


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_urlsafe(16)  # JWT ID for session tracking
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode JWT token

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """
    Authenticate user credentials

    Returns:
        User object if authentication successful, None otherwise
    """
    user = db.query(User).filter(User.username == username).first()

    if not user:
        return None

    if not user.is_active:
        return None

    # Check if account is locked
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        return None

    if not verify_password(password, user.hashed_password):
        # Increment failed login attempts
        user.failed_login_attempts += 1

        # Lock account after 5 failed attempts
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)

        db.commit()
        return None

    # Reset failed login attempts on successful login
    user.failed_login_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    user.locked_until = None
    db.commit()

    return user


def check_permissions(user_role: str, required_role: str) -> bool:
    """
    Check if user role has sufficient permissions

    Role hierarchy: admin > analyst > auditor > viewer
    """
    role_hierarchy = {
        UserRole.ADMIN: 4,
        UserRole.ANALYST: 3,
        UserRole.AUDITOR: 2,
        UserRole.VIEWER: 1
    }

    user_level = role_hierarchy.get(user_role, 0)
    required_level = role_hierarchy.get(required_role, 0)

    return user_level >= required_level


def log_audit_event(
    db: Session,
    user_id: Optional[int],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    error_message: Optional[str] = None
):
    """Log security audit event"""
    audit_log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details,
        success=success,
        error_message=error_message
    )

    db.add(audit_log)
    db.commit()


def create_api_key(user_id: int, name: str) -> tuple[str, str]:
    """
    Create API key for service authentication

    Returns:
        Tuple of (api_key, key_hash)
    """
    # Generate random API key
    api_key = f"nm_{secrets.token_urlsafe(32)}"

    # Create hash for storage
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    return api_key, key_hash


def verify_api_key(db: Session, api_key: str) -> Optional[User]:
    """Verify API key and return associated user"""
    from app.db.models_auth import APIKey

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    api_key_obj = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()

    if not api_key_obj:
        return None

    # Check expiration
    if api_key_obj.expires_at and api_key_obj.expires_at < datetime.now(timezone.utc):
        return None

    # Update last used timestamp
    api_key_obj.last_used = datetime.now(timezone.utc)
    db.commit()

    return api_key_obj.user


def create_session(
    db: Session,
    user: User,
    token_jti: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> UserSession:
    """Create user session record"""
    session = UserSession(
        user_id=user.id,
        token_jti=token_jti,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    db.add(session)
    db.commit()
    db.refresh(session)

    return session


def revoke_session(db: Session, token_jti: str, reason: str = "logout"):
    """Revoke user session"""
    session = db.query(UserSession).filter(UserSession.token_jti == token_jti).first()

    if session:
        session.revoked_at = datetime.now(timezone.utc)
        session.revoked_reason = reason
        db.commit()


def cleanup_expired_sessions(db: Session):
    """Clean up expired sessions (called periodically)"""
    expired_sessions = db.query(UserSession).filter(
        UserSession.expires_at < datetime.now(timezone.utc),
        UserSession.revoked_at.is_(None)
    ).all()

    for session in expired_sessions:
        session.revoked_at = datetime.now(timezone.utc)
        session.revoked_reason = "expired"

    db.commit()

    return len(expired_sessions)