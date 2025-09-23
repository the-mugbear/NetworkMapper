"""
Audit Logging API Endpoints

Endpoints for audit trail logging and retrieval.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.db.models_auth import User
from app.api.v1.endpoints.auth import get_current_user
from app.core.security import log_audit_event

router = APIRouter()


class AuditLogRequest(BaseModel):
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AuditLogResponse(BaseModel):
    message: str
    audit_id: Optional[int] = None


def get_client_info(request: Request) -> Dict[str, Optional[str]]:
    """Extract client information from request"""
    return {
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent")
    }


@router.post("/log", response_model=AuditLogResponse)
def create_audit_log(
    audit_data: AuditLogRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create an audit log entry"""
    client_info = get_client_info(request)

    try:
        # Log the audit event
        audit_id = log_audit_event(
            db=db,
            user_id=current_user.id,
            action=audit_data.action,
            resource_type=audit_data.resource_type,
            resource_id=audit_data.resource_id,
            details=audit_data.details or {},
            **client_info
        )

        return AuditLogResponse(
            message="Audit log created successfully",
            audit_id=audit_id
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create audit log: {str(e)}"
        )


@router.get("/logs")
def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get audit logs (admin only)"""
    # Only admins can view audit logs
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can view audit logs"
        )

    # Import here to avoid circular imports
    from app.db.models_auth import AuditLog

    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    # Order by most recent first
    query = query.order_by(AuditLog.created_at.desc())

    # Apply pagination
    logs = query.offset(skip).limit(limit).all()

    return {
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "details": log.details,
                "success": log.success,
                "error_message": log.error_message,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "created_at": log.created_at
            }
            for log in logs
        ],
        "total": query.count(),
        "skip": skip,
        "limit": limit
    }


@router.get("/stats")
def get_audit_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get audit statistics (admin only)"""
    # Only admins can view audit stats
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can view audit statistics"
        )

    # Import here to avoid circular imports
    from app.db.models_auth import AuditLog
    from sqlalchemy import func

    # Get basic stats
    total_logs = db.query(AuditLog).count()
    successful_logs = db.query(AuditLog).filter(AuditLog.success == True).count()
    failed_logs = db.query(AuditLog).filter(AuditLog.success == False).count()

    # Get recent activity (last 24 hours)
    twenty_four_hours_ago = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    recent_logs = db.query(AuditLog).filter(
        AuditLog.created_at >= twenty_four_hours_ago
    ).count()

    # Get top actions
    top_actions = db.query(
        AuditLog.action,
        func.count(AuditLog.id).label('count')
    ).group_by(AuditLog.action).order_by(
        func.count(AuditLog.id).desc()
    ).limit(10).all()

    # Get top users
    top_users = db.query(
        AuditLog.user_id,
        func.count(AuditLog.id).label('count')
    ).group_by(AuditLog.user_id).order_by(
        func.count(AuditLog.id).desc()
    ).limit(10).all()

    return {
        "total_logs": total_logs,
        "successful_logs": successful_logs,
        "failed_logs": failed_logs,
        "recent_logs_24h": recent_logs,
        "top_actions": [
            {"action": action, "count": count}
            for action, count in top_actions
        ],
        "top_users": [
            {"user_id": user_id, "count": count}
            for user_id, count in top_users
        ]
    }