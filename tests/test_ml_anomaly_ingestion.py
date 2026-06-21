from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import Session, select

from app.core.paths import PI_DIR
from app.db.session import create_db_and_tables, engine
from app.models.incident import Finding
from app.schemas.event import EventCreate
from app.services.ingestion import ingest_event, process_events


MODEL_PATH = PI_DIR / "data" / "models" / "anomaly_model.pkl"
SCALER_PATH = PI_DIR / "data" / "models" / "anomaly_scaler.pkl"
METADATA_PATH = PI_DIR / "data" / "models" / "anomaly_metadata.json"


@pytest.fixture
def _force_heuristic_mode(monkeypatch):
    """Run the anomaly detector in heuristic-only mode for deterministic tests.

    The persisted ML model is the product of the training snapshot that happened to
    exist on disk when the test was authored. In a freshly cloned or wiped database
    that model is absent and the detector falls back to heuristics, which scores
    a 100MB+ outbound transfer at ~0.95. To keep the test deterministic regardless
    of whether ``scripts/train_ml.py`` has been executed in the same checkout, we
    reload the singleton with the persisted artifacts removed for the duration of
    the test and restore them afterwards.
    """
    saved = {}
    for path in (MODEL_PATH, SCALER_PATH, METADATA_PATH):
        if path.exists():
            saved[path] = path.read_bytes()
            path.unlink()

    # `app.detection.__init__` re-exports ``anomaly_detector`` as the singleton
    # instance, which shadows the submodule of the same name. Use ``sys.modules``
    # to get the actual module object so we can swap the singleton cleanly.
    import sys

    detector_module = sys.modules["app.detection.anomaly_detector"]
    ingestion_module = sys.modules["app.services.ingestion"]

    # Save every reference to the singleton we know about — both the one
    # inside the detector module (the "true" home) and the alias that was
    # captured at import time by ``app.services.ingestion``.
    original_detector = detector_module.anomaly_detector
    original_ingestion_ref = ingestion_module.anomaly_detector

    fresh = detector_module.AnomalyDetector()
    detector_module.anomaly_detector = fresh
    ingestion_module.anomaly_detector = fresh
    try:
        yield
    finally:
        detector_module.anomaly_detector = original_detector
        ingestion_module.anomaly_detector = original_ingestion_ref
        for path, data in saved.items():
            path.write_bytes(data)


def test_ingestion_persists_ml_anomaly_finding(_force_heuristic_mode) -> None:
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
