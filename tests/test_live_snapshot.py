from __future__ import annotations

from fastapi.testclient import TestClient

from app.web.server import create_app


def test_live_snapshot_shape() -> None:
    client = TestClient(create_app())

    response = client.get("/api/v1/live/snapshot")

    assert response.status_code == 200
    payload = response.json()
    assert "timestamp" in payload
    assert "stats" in payload
    assert "incidents" in payload
    assert "actions" in payload
    assert "total_events" in payload["stats"]
