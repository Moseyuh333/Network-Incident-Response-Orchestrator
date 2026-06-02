"""Incident data model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlmodel import Field, Relationship, SQLModel


class Incident(SQLModel, table=True):
    """Aggregated security incident derived from one or more events."""

    __tablename__ = "incidents"

    id: int | None = Field(default=None, primary_key=True)
    title: str = Field(index=True)
    incident_type: str = Field(index=True)
    severity: str = Field(default="medium", index=True)
    confidence: float = Field(default=0.0)
    status: str = Field(default="open", index=True)
    source_ip: str | None = Field(default=None, index=True)
    destination_ip: str | None = Field(default=None, index=True)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[dict[str, Any]] | None = Field(default=None)
    llm_summary: str | None = None
    llm_report: str | None = None
    recommended_actions: list[dict[str, Any]] | None = Field(default=None)
    mitre_mapping: list[dict[str, str]] | None = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    response_actions: list["ResponseAction"] = Relationship(back_populates="incident")


class ResponseAction(SQLModel, table=True):
    """Recorded response action taken against an incident."""

    __tablename__ = "response_actions"

    id: int | None = Field(default=None, primary_key=True)
    incident_id: int = Field(foreign_key="incidents.id", index=True)
    action_type: str = Field(index=True)
    status: str = Field(default="pending", index=True)
    simulated: bool = Field(default=True)
    requires_approval: bool = Field(default=True)
    result: dict[str, Any] | None = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    incident: Incident = Relationship(back_populates="response_actions")
