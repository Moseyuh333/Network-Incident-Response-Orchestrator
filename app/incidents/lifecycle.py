"""Validated incident status transitions."""

from __future__ import annotations

from datetime import datetime

from sqlmodel import Session

from app.models.incident import Incident
from app.services.ingestion import audit

TRANSITIONS = {
    "new": {"triaging", "cancelled", "false_positive"},
    "triaging": {"investigating", "false_positive", "cancelled"},
    "investigating": {"awaiting_approval", "monitoring", "resolved", "false_positive"},
    "awaiting_approval": {"containing", "investigating", "cancelled"},
    "containing": {"monitoring", "investigating"},
    "monitoring": {"resolved", "investigating"},
    "resolved": {"closed", "monitoring"},
    "closed": set(),
    "false_positive": {"closed"},
    "cancelled": {"closed"},
}


def transition_incident(
    session: Session,
    incident: Incident,
    new_status: str,
    actor: str = "operator",
) -> Incident:
    """Transition an incident status or raise a useful error."""
    allowed = TRANSITIONS.get(incident.status, set())
    if new_status not in allowed:
        raise ValueError(f"invalid transition {incident.status!r} -> {new_status!r}")
    before = incident.model_dump()
    incident.status = new_status
    incident.updated_at = datetime.utcnow()
    session.add(incident)
    session.commit()
    session.refresh(incident)
    audit(session, actor, "incident.status", "incident", incident.public_id, before, incident.model_dump())
    return incident
