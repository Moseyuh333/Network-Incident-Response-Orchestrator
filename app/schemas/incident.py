"""Incident request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MitreMapping(BaseModel):
    tactic: str
    technique: str
    technique_id: str


class RecommendedAction(BaseModel):
    action: str
    risk: str = "low"
    requires_human_approval: bool = True


class IncidentCreate(BaseModel):
    """Schema for manual incident creation."""

    title: str = Field(..., max_length=500)
    incident_type: str = "unknown"
    severity: str = "medium"
    source_ip: str | None = None
    destination_ip: str | None = None
    evidence: list[dict[str, Any]] | None = None


class IncidentResponse(BaseModel):
    """Schema returned for incident list/individual query."""

    id: int
    title: str
    incident_type: str
    severity: str
    confidence: float
    status: str
    source_ip: str | None
    destination_ip: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    llm_summary: str | None
    recommended_actions: list[dict[str, Any]] | None
    mitre_mapping: list[dict[str, str]] | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class IncidentDetail(IncidentResponse):
    """Extended incident detail including full report and response actions."""

    llm_report: str | None
    evidence: list[dict[str, Any]] | None
    response_actions: list[dict[str, Any]] | None


class AnalyzeRequest(BaseModel):
    """Request body for triggering LLM analysis."""

    force: bool = Field(
        False, description="Re-analyze even if llm_summary already present"
    )


class LLMOutputSchema(BaseModel):
    """Structured output schema expected from the LLM."""

    summary: str
    incident_type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_summary: str = ""
    mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    report: str = ""


class RespondRequest(BaseModel):
    """Request body for triggering response actions."""

    action_types: list[str] | None = Field(
        None, description="Specific actions to run; omit for playbook default"
    )
    dry_run: bool = Field(
        True, description="If true, only simulate (never real-block)"
    )
