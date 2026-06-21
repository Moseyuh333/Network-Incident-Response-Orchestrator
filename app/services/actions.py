"""Persistent response action workflow."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlmodel import Session

from app.core.json import jsonable
from app.models.incident import ResponseAction
from app.response.policy import evaluate_action, execute_simulation, rollback_simulation
from app.services.ingestion import audit


def propose_action(
    session: Session,
    incident_id: int,
    action_type: str,
    arguments: dict[str, Any] | None,
    proposed_by: str = "agent",
) -> ResponseAction:
    policy = evaluate_action(action_type, arguments)
    if policy["decision"] == "denied":
        raise ValueError(f"action denied by policy: {action_type}")
    status = "awaiting_approval" if policy["requires_approval"] else "approved"
    action = ResponseAction(
        incident_id=incident_id,
        action_type=action_type,
        arguments=arguments or {},
        risk=policy["risk"],
        status=status,
        requires_approval=policy["requires_approval"],
        proposed_by=proposed_by,
    )
    session.add(action)
    session.commit()
    session.refresh(action)
    audit(session, proposed_by, "action.propose", "action", str(action.id), after=action.model_dump())
    return action


def approve_action(session: Session, action: ResponseAction, actor: str = "operator") -> ResponseAction:
    before = action.model_dump()
    if action.status != "awaiting_approval":
        raise ValueError(f"cannot approve action in state {action.status}")
    action.status = "approved"
    action.approved_by = actor
    action.approval_timestamp = datetime.utcnow()
    action.updated_at = datetime.utcnow()
    session.add(action)
    session.commit()
    session.refresh(action)
    audit(session, actor, "action.approve", "action", str(action.id), before, action.model_dump())
    return action


def reject_action(session: Session, action: ResponseAction, actor: str = "operator") -> ResponseAction:
    before = action.model_dump()
    if action.status != "awaiting_approval":
        raise ValueError(f"cannot reject action in state {action.status}")
    action.status = "rejected"
    action.approved_by = actor
    action.approval_timestamp = datetime.utcnow()
    action.updated_at = datetime.utcnow()
    session.add(action)
    session.commit()
    session.refresh(action)
    audit(session, actor, "action.reject", "action", str(action.id), before, action.model_dump())
    return action


def execute_action(session: Session, action: ResponseAction, actor: str = "operator") -> ResponseAction:
    before = action.model_dump()
    if action.status not in {"approved"}:
        raise ValueError(f"cannot execute action in state {action.status}")
    action.status = "completed"
    action.result = jsonable(execute_simulation(action))
    action.verification_result = {"verified": True, "mode": "simulation"}
    action.rollback_data = jsonable({"previous_state": before})
    action.updated_at = datetime.utcnow()
    session.add(action)
    session.commit()
    session.refresh(action)
    audit(session, actor, "action.execute", "action", str(action.id), before, action.model_dump())
    return action


def rollback_action(session: Session, action: ResponseAction, actor: str = "operator") -> ResponseAction:
    before = action.model_dump()
    if action.status != "completed":
        raise ValueError(f"cannot rollback action in state {action.status}")
    action.status = "rolled_back"
    action.result = jsonable(rollback_simulation(action))
    action.updated_at = datetime.utcnow()
    session.add(action)
    session.commit()
    session.refresh(action)
    audit(session, actor, "action.rollback", "action", str(action.id), before, action.model_dump())
    return action
