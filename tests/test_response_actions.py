from __future__ import annotations

import pytest
from uuid import uuid4
from sqlmodel import Session

from app.db.session import create_db_and_tables, engine
from app.models.incident import Incident
from app.response.policy import evaluate_action
from app.services.actions import approve_action, execute_action, propose_action, rollback_action


def test_high_risk_action_requires_approval_and_rolls_back() -> None:
    create_db_and_tables()
    with Session(engine) as session:
        incident = Incident(public_id=f"INC-TEST-{uuid4()}", title="test", incident_type="Port Scan")
        session.add(incident)
        session.commit()
        session.refresh(incident)

        action = propose_action(session, incident.id, "simulate_block_ip", {"ip": "203.0.113.77"})
        assert action.status == "awaiting_approval"
        approved = approve_action(session, action)
        assert approved.status == "approved"
        executed = execute_action(session, approved)
        assert executed.status == "completed"
        rolled_back = rollback_action(session, executed)
        assert rolled_back.status == "rolled_back"


def test_protected_ip_cannot_be_blocked() -> None:
    with pytest.raises(ValueError):
        evaluate_action("simulate_block_ip", {"ip": "127.0.0.1"})
