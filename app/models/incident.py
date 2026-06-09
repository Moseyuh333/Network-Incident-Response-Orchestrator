"""Incident data model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


class Incident(SQLModel, table=True):
    """Aggregated security incident derived from one or more events."""

    __tablename__ = "incidents"

    id: int | None = Field(default=None, primary_key=True)
    public_id: str = Field(default="", index=True, unique=True)
    title: str = Field(index=True)
    incident_type: str = Field(index=True)
    severity: str = Field(default="medium", index=True)
    confidence: float = Field(default=0.0)
    status: str = Field(default="new", index=True)
    source_ip: str | None = Field(default=None, index=True)
    destination_ip: str | None = Field(default=None, index=True)
    assigned_to: str | None = Field(default=None, index=True)
    summary: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[dict[str, Any]] | None = Field(default=None, sa_column=Column(JSON))
    llm_summary: str | None = None
    llm_report: str | None = None
    recommended_actions: list[Any] | None = Field(default=None, sa_column=Column(JSON))
    mitre_mapping: list[dict[str, str]] | None = Field(default=None, sa_column=Column(JSON))
    asset_context: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    correlation_reason: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class Finding(SQLModel, table=True):
    """Deterministic rule or ML finding."""

    __tablename__ = "findings"

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int | None = Field(default=None, foreign_key="incidents.id", index=True)
    detector_id: str = Field(index=True)
    detector_version: str = "1.0"
    incident_type: str = Field(index=True)
    severity: str = Field(index=True)
    confidence: float = 0.0
    source_ip: str | None = Field(default=None, index=True)
    destination_ip: str | None = Field(default=None, index=True)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence_summary: str = ""
    related_event_ids: list[int] | None = Field(default=None, sa_column=Column(JSON))
    ml_score: float | None = None
    recommended_playbooks: list[str] | None = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class ResponseAction(SQLModel, table=True):
    """Recorded response action taken against an incident."""

    __tablename__ = "response_actions"

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="incidents.id", index=True)
    action_type: str = Field(index=True)
    plugin: str = "simulation"
    arguments: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    risk: str = Field(default="low", index=True)
    status: str = Field(default="proposed", index=True)
    simulated: bool = Field(default=True)
    requires_approval: bool = Field(default=True)
    proposed_by: str = "agent"
    approved_by: str | None = None
    approval_timestamp: datetime | None = None
    result: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    verification_result: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    rollback_data: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    expiration_time: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class AgentRun(SQLModel, table=True):
    """Persisted AI agent run."""

    __tablename__ = "agent_runs"

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int | None = Field(default=None, foreign_key="incidents.id", index=True)
    task: str
    started_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    ended_at: datetime | None = None
    provider: str = ""
    model: str = ""
    status: str = Field(default="running", index=True)
    final_response: str | None = None
    error: str | None = None
    usage_metadata: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))


class ToolCall(SQLModel, table=True):
    """Persisted agent tool call."""

    __tablename__ = "tool_calls"

    id: int | None = Field(default=None, primary_key=True)
    agent_run_id: int = Field(foreign_key="agent_runs.id", index=True)
    tool_name: str = Field(index=True)
    sanitized_arguments: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    started_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    ended_at: datetime | None = None
    result_summary: str | None = None
    status: str = Field(default="running", index=True)
    error: str | None = None
    risk_level: str = "read_only"
    approval_required: bool = False


class AuditEntry(SQLModel, table=True):
    """Auditable state transition or operator action."""

    __tablename__ = "audit_entries"

    id: int | None = Field(default=None, primary_key=True)
    actor: str = Field(index=True)
    action: str = Field(index=True)
    target_type: str = Field(index=True)
    target_id: str = Field(index=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    before_state: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    after_state: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    result: str = "success"
    correlation_id: str | None = Field(default=None, index=True)
