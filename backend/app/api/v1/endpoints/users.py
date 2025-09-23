"""
User Management API Endpoints

Endpoints for admin user management including listing users, updating profiles,
changing roles, activating/deactivating accounts.
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.db.session import get_db
from app.db.models_auth import User, UserRole
from app.core.security import (
    get_password_hash,
    validate_password_strength,
    log_audit_event,
    check_permissions
)
from app.api.v1.endpoints.auth import get_current_user, require_role, get_client_info

router = APIRouter()


# Pydantic models
class UserListItem(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    last_login: Optional[datetime]
    created_at: datetime
    created_by_id: Optional[int]


class UserUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class AdminPasswordResetRequest(BaseModel):
    new_password: str


class UserProfileUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None


@router.get("/", response_model=List[UserListItem])
def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """List all users (admin only)"""
    users = db.query(User).offset(skip).limit(limit).all()

    return [
        UserListItem(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
            last_login=user.last_login,
            created_at=user.created_at,
            created_by_id=user.created_by_id
        )
        for user in users
    ]


@router.get("/{user_id}", response_model=UserListItem)
def get_user(
    user_id: int,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """Get specific user details (admin only)"""
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return UserListItem(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
        created_by_id=user.created_by_id
    )


@router.put("/{user_id}", response_model=UserListItem)
def update_user(
    user_id: int,
    update_data: UserUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """Update user details (admin only)"""
    client_info = get_client_info(request)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent admin from demoting themselves
    if user_id == current_user.id and update_data.role and update_data.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own admin role"
        )

    # Prevent admin from deactivating themselves
    if user_id == current_user.id and update_data.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )

    changes = {}

    # Update fields if provided
    if update_data.email is not None:
        # Check if email is already taken by another user
        existing_user = db.query(User).filter(
            User.email == update_data.email,
            User.id != user_id
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )
        changes["email"] = {"old": user.email, "new": update_data.email}
        user.email = update_data.email

    if update_data.full_name is not None:
        changes["full_name"] = {"old": user.full_name, "new": update_data.full_name}
        user.full_name = update_data.full_name

    if update_data.role is not None:
        if update_data.role not in [UserRole.ADMIN, UserRole.ANALYST, UserRole.AUDITOR, UserRole.VIEWER]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid role"
            )
        changes["role"] = {"old": user.role, "new": update_data.role}
        user.role = update_data.role

    if update_data.is_active is not None:
        changes["is_active"] = {"old": user.is_active, "new": update_data.is_active}
        user.is_active = update_data.is_active

    db.commit()

    # Log the changes
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="user_updated",
        resource_type="user",
        resource_id=str(user_id),
        details={"changes": changes, "target_user": user.username},
        **client_info
    )

    return UserListItem(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
        created_by_id=user.created_by_id
    )


@router.post("/{user_id}/reset-password")
def admin_reset_password(
    user_id: int,
    password_data: AdminPasswordResetRequest,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """Reset user password (admin only)"""
    client_info = get_client_info(request)

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Validate password strength
    password_validation = validate_password_strength(password_data.new_password)
    if not password_validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {', '.join(password_validation['errors'])}"
        )

    # Update password
    user.hashed_password = get_password_hash(password_data.new_password)
    user.password_changed_at = datetime.utcnow()

    db.commit()

    # Log password reset
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="admin_password_reset",
        resource_type="user",
        resource_id=str(user_id),
        details={"target_user": user.username},
        **client_info
    )

    return {"message": f"Password reset for user {user.username}"}


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """Delete user (admin only)"""
    client_info = get_client_info(request)

    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    username = user.username  # Store before deletion

    db.delete(user)
    db.commit()

    # Log user deletion
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="user_deleted",
        resource_type="user",
        resource_id=str(user_id),
        details={"deleted_username": username},
        **client_info
    )

    return {"message": f"User {username} deleted successfully"}


@router.put("/profile")
def update_own_profile(
    profile_data: UserProfileUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update own profile (any authenticated user)"""
    client_info = get_client_info(request)

    changes = {}

    if profile_data.email is not None:
        # Check if email is already taken by another user
        existing_user = db.query(User).filter(
            User.email == profile_data.email,
            User.id != current_user.id
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )
        changes["email"] = {"old": current_user.email, "new": profile_data.email}
        current_user.email = profile_data.email

    if profile_data.full_name is not None:
        changes["full_name"] = {"old": current_user.full_name, "new": profile_data.full_name}
        current_user.full_name = profile_data.full_name

    db.commit()

    # Log profile update
    log_audit_event(
        db=db,
        user_id=current_user.id,
        action="profile_updated",
        details={"changes": changes},
        **client_info
    )

    return {"message": "Profile updated successfully"}