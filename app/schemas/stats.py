"""Dashboard statistics schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class SeverityCount(BaseModel):
    severity: str
    count: int


class StatsResponse(BaseModel):
    total_events: int
    total_incidents: int
    open_incidents: int
    closed_incidents: int
    severity_distribution: list[SeverityCount]
    recent_incidents: list[dict[str, Any]]
    events_last_24h: int
    incidents_last_24h: int
