from __future__ import annotations

import logging
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session, selectinload

from app.db import models
from app.db.models import HostFollow, FollowStatus, HostNote, NoteStatus

logger = logging.getLogger(__name__)


class HostFollowService:
    def __init__(self, db: Session):
        self.db = db

    def get_follow(self, host_id: int, user_id: int) -> Optional[HostFollow]:
        return (
            self.db.query(HostFollow)
            .filter(HostFollow.host_id == host_id, HostFollow.user_id == user_id)
            .first()
        )

    def set_follow_status(self, host_id: int, user_id: int, status: FollowStatus) -> HostFollow:
        follow = self.get_follow(host_id, user_id)
        if follow:
            follow.status = status
        else:
            follow = HostFollow(host_id=host_id, user_id=user_id, status=status)
            self.db.add(follow)
        self.db.commit()
        self.db.refresh(follow)
        return follow

    def unfollow(self, host_id: int, user_id: int) -> None:
        follow = self.get_follow(host_id, user_id)
        if follow:
            self.db.delete(follow)
            self.db.commit()

    def list_notes(self, host_id: int, limit: int = 50) -> List[HostNote]:
        return (
            self.db.query(HostNote)
            .filter(HostNote.host_id == host_id)
            .options(selectinload(HostNote.author))
            .order_by(HostNote.created_at.desc())
            .limit(limit)
            .all()
        )

    def create_note(
        self,
        host_id: int,
        user_id: int,
        body: str,
        status: NoteStatus = NoteStatus.OPEN,
    ) -> HostNote:
        note = HostNote(host_id=host_id, user_id=user_id, body=body, status=status)
        self.db.add(note)
        self.db.commit()
        self.db.refresh(note)
        self.db.refresh(note, attribute_names=["author"])
        return note

    def update_note(
        self,
        note_id: int,
        user_id: int,
        body: Optional[str] = None,
        status: Optional[NoteStatus] = None,
        host_id: Optional[int] = None,
    ) -> HostNote:
        note = self.db.query(HostNote).filter(HostNote.id == note_id).first()
        if not note:
            raise ValueError("Note not found")
        if note.user_id != user_id:
            raise PermissionError("Cannot modify another user's note")
        if host_id is not None and note.host_id != host_id:
            raise ValueError("Note not found")
        if body is not None:
            note.body = body
        if status is not None:
            note.status = status
        self.db.commit()
        self.db.refresh(note)
        self.db.refresh(note, attribute_names=["author"])
        return note

    def delete_note(self, note_id: int, user_id: int, host_id: Optional[int] = None) -> None:
        note = self.db.query(HostNote).filter(HostNote.id == note_id).first()
        if not note:
            raise ValueError("Note not found")
        if note.user_id != user_id:
            raise PermissionError("Cannot delete another user's note")
        if host_id is not None and note.host_id != host_id:
            raise ValueError("Note not found")
        self.db.delete(note)
        self.db.commit()

    def get_dashboard_activity(self, user_id: int, limit: int = 5) -> Dict[str, object]:
        """Return recent note activity and follow counts for dashboard display."""
        total_notes = (
            self.db.query(func.count(HostNote.id))
            .filter(HostNote.user_id == user_id)
            .scalar()
            or 0
        )

        follows_count = (
            self.db.query(func.count(HostFollow.id))
            .filter(HostFollow.user_id == user_id)
            .scalar()
            or 0
        )

        notes = (
            self.db.query(HostNote)
            .filter(HostNote.user_id == user_id)
            .options(selectinload(HostNote.host))
            .order_by(func.coalesce(HostNote.updated_at, HostNote.created_at).desc())
            .limit(limit)
            .all()
        )

        active_host_ids = {note.host_id for note in notes}

        recent_notes = []
        for note in notes:
            host = note.host
            recent_notes.append(
                {
                    "note_id": note.id,
                    "host_id": note.host_id,
                    "ip_address": host.ip_address if host else "unknown",
                    "hostname": host.hostname if host else None,
                    "status": note.status,
                    "preview": (note.body[:140] + "…") if len(note.body) > 140 else note.body,
                    "created_at": note.created_at,
                    "updated_at": note.updated_at,
                }
            )

        return {
            "total_notes": total_notes,
            "active_host_count": len(active_host_ids),
            "following_count": follows_count,
            "recent_notes": recent_notes,
        }
