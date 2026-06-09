from __future__ import annotations

from fastapi.testclient import TestClient

from app.web.server import create_app


def test_bulk_ingestion_persists_events_findings_and_incidents(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'niro-test.db'}")
    client = TestClient(create_app())
    events = [
        {
            "external_event_id": f"scan-{port}",
            "timestamp": f"2026-06-05T15:19:{i:02d}Z",
            "sensor": "test-sensor",
            "source_ip": "203.0.113.77",
            "destination_ip": "10.10.20.15",
            "source_port": 51000 + i,
            "destination_port": port,
            "protocol": "TCP",
            "event_type": "firewall",
            "action": "denied",
        }
        for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 445, 1433, 3389])
    ]

    response = client.post("/api/v1/events/bulk", json={"events": events})
    stats = client.get("/api/v1/dashboard/stats").json()
    incidents = client.get("/api/v1/incidents").json()

    assert response.status_code == 200
    assert response.json()["ingested"] == len(events)
    assert stats["total_events"] >= len(events)
    assert stats["findings"] >= 1
    assert incidents
    assert incidents[0]["public_id"].startswith("INC-")
