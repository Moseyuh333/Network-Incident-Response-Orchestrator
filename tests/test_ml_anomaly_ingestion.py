from __future__ import annotations

from uuid import uuid4

from sqlmodel import Session, select

from app.db.session import create_db_and_tables, engine
from app.models.incident import Finding
from app.schemas.event import EventCreate
from app.services.ingestion import ingest_event, process_events


def test_ingestion_persists_ml_anomaly_finding() -> None:
    create_db_and_tables()
    external_id = f"ml-anomaly-{uuid4()}"
    with Session(engine) as session:
        event = ingest_event(
            session,
            EventCreate(
                external_event_id=external_id,
                source_ip="10.10.20.15",
                destination_ip="198.51.100.55",
                destination_port=443,
                protocol="TCP",
                event_type="http",
                bytes_out=125 * 1_048_576,
            ),
        )
        incidents = process_events(session, [event])
        findings = session.exec(
            select(Finding).where(Finding.incident_type == "Anomalous Network Activity")
        ).all()

    assert incidents
    assert any(finding.ml_score and finding.ml_score >= 0.92 for finding in findings)
