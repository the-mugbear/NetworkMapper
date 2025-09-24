"""
Authentication and User Management Models

Models for user accounts, roles, and session management for security intelligence platform.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base
from enum import Enum
import datetime


class UserRole(str, Enum):
    ADMIN = "admin"          # Full system access, user management
    ANALYST = "analyst"      # Read/write access to security data
    VIEWER = "viewer"        # Read-only access to dashboards
    AUDITOR = "auditor"      # Read-only access with audit logs


class User(Base):
    """User accounts for the security platform"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=True, index=True)
    hashed_password = Column(String(255), nullable=False)

    # User profile
    full_name = Column(String(100))
    role = Column(String(20), nullable=False, default=UserRole.VIEWER)

    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime(timezone=True))

    # Security settings
    password_changed_at = Column(DateTime(timezone=True), server_default=func.now())
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))

    # Audit fields
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by_id = Column(Integer, ForeignKey("users.id"))

    # Relationships
    created_by = relationship("User", remote_side=[id])
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    host_follows = relationship("HostFollow", back_populates="user", cascade="all, delete-orphan")
    host_notes = relationship("HostNote", back_populates="author", cascade="all, delete-orphan")


class UserSession(Base):
    """Active user sessions for token management"""
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_jti = Column(String(36), unique=True, nullable=False, index=True)  # JWT ID

    # Session metadata
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    device_info = Column(JSON)

    # Session lifecycle
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True))
    revoked_reason = Column(String(100))

    # Relationships
    user = relationship("User", back_populates="sessions")


class AuditLog(Base):
    """Security audit logging for compliance and monitoring"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))

    # Action details
    action = Column(String(50), nullable=False, index=True)  # login, logout, view_host, upload_scan, etc.
    resource_type = Column(String(50))  # host, scan, user, etc.
    resource_id = Column(String(50))

    # Event metadata
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # Additional context
    details = Column(JSON)  # Flexible field for action-specific data
    success = Column(Boolean, default=True)
    error_message = Column(Text)

    # Relationships
    user = relationship("User", back_populates="audit_logs")


class APIKey(Base):
    """API keys for service-to-service authentication"""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Key details
    name = Column(String(100), nullable=False)  # Human-readable name
    key_hash = Column(String(255), nullable=False, unique=True)
    key_prefix = Column(String(10), nullable=False, index=True)  # First few chars for identification

    # Permissions and scope
    scopes = Column(JSON)  # List of allowed operations
    allowed_ips = Column(JSON)  # IP whitelist

    # Lifecycle
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    last_used = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)

    # Relationships
    user = relationship("User")


class SecurityPolicy(Base):
    """System security policies and configuration"""
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, index=True)

    # Policy settings
    password_min_length = Column(Integer, default=12)
    password_require_uppercase = Column(Boolean, default=True)
    password_require_lowercase = Column(Boolean, default=True)
    password_require_numbers = Column(Boolean, default=True)
    password_require_symbols = Column(Boolean, default=True)
    password_expiry_days = Column(Integer, default=90)

    # Session security
    session_timeout_minutes = Column(Integer, default=480)  # 8 hours
    max_concurrent_sessions = Column(Integer, default=3)

    # Account lockout
    max_failed_login_attempts = Column(Integer, default=5)
    lockout_duration_minutes = Column(Integer, default=30)

    # Audit settings
    audit_retention_days = Column(Integer, default=365)
    require_audit_login = Column(Boolean, default=True)
    require_audit_data_access = Column(Boolean, default=True)

    # Policy metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by_id = Column(Integer, ForeignKey("users.id"))

    # Relationships
    updated_by = relationship("User")
