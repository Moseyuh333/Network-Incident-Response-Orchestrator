"""Event request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    """Schema for ingesting a single event."""

    external_event_id: str | None = None
    timestamp: datetime | None = None
    sensor: str | None = None
    source_type: str | None = None
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    event_type: str = "unknown"
    action: str | None = None
    username: str | None = None
    url: str | None = None
    domain: str | None = None
    flow_id: str | None = None
    severity: str | None = None
    user_agent: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    raw: dict[str, Any] | None = None


class EventResponse(BaseModel):
    """Schema returned for an event."""

    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    event_type: str
    action: str | None
    username: str | None
    url: str | None
    user_agent: str | None
    bytes_in: int
    bytes_out: int
    created_at: datetime

    model_config = {"from_attributes": True}


class BulkEventsRequest(BaseModel):
    """Schema for bulk event ingestion."""

    events: list[EventCreate] = Field(..., max_length=10000)
