from __future__ import annotations

from uuid import uuid4

from sqlmodel import Session

from app.db.session import create_db_and_tables, engine
from app.models.incident import Finding, Incident
from app.services.ingestion import correlate_finding


def test_correlation_does_not_reopen_resolved_incident() -> None:
    create_db_and_tables()
    with Session(engine) as session:
        resolved = Incident(
            public_id=f"INC-RESOLVED-{uuid4()}",
            title="resolved scan",
            incident_type="Port Scan",
            status="resolved",
            source_ip="203.0.113.200",
            destination_ip="10.10.20.15",
        )
        session.add(resolved)
        session.commit()
        session.refresh(resolved)
        resolved_id = resolved.id
        finding = Finding(
            detector_id="rule.port_scan",
            incident_type="Port Scan",
            severity="medium",
            confidence=0.8,
            source_ip="203.0.113.200",
            destination_ip="10.10.20.15",
            evidence_summary="new scan after resolution",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)

        incident = correlate_finding(session, finding, {"recommended_actions": []})
        incident_id = incident.id
        incident_status = incident.status

    assert incident_id != resolved_id
    assert incident_status == "new"
