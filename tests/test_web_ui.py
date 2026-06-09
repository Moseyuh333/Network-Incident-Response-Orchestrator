from __future__ import annotations

from fastapi.testclient import TestClient

from app.web.server import create_app


def test_web_status_and_index_load() -> None:
    client = TestClient(create_app())

    index = client.get("/")
    status = client.get("/api/status")

    assert index.status_code == 200
    assert "Agent Console" in index.text
    assert status.status_code == 200
    assert "llm" in status.json()
    assert status.json()["sample_alert"]["alert_id"] == "ALERT-2026-09-001"
    assert "resources" in status.json()


def test_web_chat_and_resource_index() -> None:
    client = TestClient(create_app())

    chat = client.post("/api/chat", json={"command": "list skills and plugins"})
    resources = client.get("/api/resources")
    skill = client.get("/api/resources/skills/SKILL.md")

    assert chat.status_code == 200
    assert chat.json()["mode"] == "resources"
    assert resources.status_code == 200
    assert resources.json()["skills"][0]["name"] == "SKILL.md"
    assert skill.status_code == 200
    assert "Network IR Orchestration Skill" in skill.json()["content"]
