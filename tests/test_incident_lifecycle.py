from __future__ import annotations

import pytest
from uuid import uuid4
from sqlmodel import Session

from app.db.session import create_db_and_tables, engine
from app.incidents.lifecycle import transition_incident
from app.models.incident import Incident


def test_incident_lifecycle_validates_transitions() -> None:
    create_db_and_tables()
    with Session(engine) as session:
        incident = Incident(public_id=f"INC-LIFE-{uuid4()}", title="life", incident_type="Web Attack")
        session.add(incident)
        session.commit()
        session.refresh(incident)

        incident = transition_incident(session, incident, "triaging")
        assert incident.status == "triaging"

        with pytest.raises(ValueError):
            transition_incident(session, incident, "closed")
