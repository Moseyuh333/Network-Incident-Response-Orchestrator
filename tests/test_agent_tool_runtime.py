from __future__ import annotations

from uuid import uuid4

from sqlmodel import Session, select

from app.db.session import create_db_and_tables, engine
from app.models.incident import Incident, ResponseAction, ToolCall
from app.services.agent_runs import run_agent_for_incident
from scripts.run_pipeline import PI_DIR


def test_agent_run_persists_tool_calls_and_only_proposes_response(monkeypatch) -> None:
    def fake_analyze(self, context):  # noqa: ANN001
        return {
            "available": False,
            "provider": "test",
            "model": "stub",
            "summary": "Stubbed analysis",
            "incident_type": context["classification"]["label"],
            "severity": context["classification"]["severity"],
            "confidence": context["classification"]["confidence"],
            "reasoning_summary": "Tool context was reviewed.",
            "mitre_mapping": [],
            "recommended_actions": [{"action": "Review proposed block", "risk": "low"}],
            "report": "# Stubbed analysis\n",
        }

    monkeypatch.setattr("app.services.agent_runs.IncidentResponseAgent.analyze", fake_analyze)
    create_db_and_tables()
    with Session(engine) as session:
        incident = Incident(
            public_id=f"INC-AGENT-{uuid4()}",
            title="Port scan from external host",
            incident_type="Port Scan",
            severity="high",
            confidence=0.9,
            source_ip="203.0.113.77",
            destination_ip="10.10.20.15",
        )
        session.add(incident)
        session.commit()
        session.refresh(incident)

        agent_run = run_agent_for_incident(
            session,
            incident.id,
            "Contain this incident and block the suspicious source in simulation mode.",
            PI_DIR,
        )

        tool_calls = session.exec(
            select(ToolCall).where(ToolCall.agent_run_id == agent_run.id).order_by(ToolCall.id)
        ).all()
        actions = session.exec(
            select(ResponseAction).where(ResponseAction.incident_id == incident.id)
        ).all()

    assert agent_run.status == "completed"
    assert {call.tool_name for call in tool_calls} >= {
        "get_incident",
        "list_findings",
        "list_related_events",
        "list_actions",
        "propose_response_action",
    }
    assert all(call.status == "completed" for call in tool_calls)
    assert len(actions) == 1
    assert actions[0].action_type == "simulate_block_ip"
    assert actions[0].status == "awaiting_approval"
