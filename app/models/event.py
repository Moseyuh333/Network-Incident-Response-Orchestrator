"""Event data model."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlmodel import Field, SQLModel


class Event(SQLModel, table=True):
    """Raw network event ingested from logs or API."""

    __tablename__ = "events"

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(index=True)
    source_ip: str = Field(index=True)
    destination_ip: str = Field(index=True)
    source_port: int | None = None
    destination_port: int | None = Field(default=None, index=True)
    protocol: str | None = None
    event_type: str = Field(default="unknown", index=True)
    action: str | None = None
    username: str | None = None
    url: str | None = None
    user_agent: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    raw: dict[str, Any] | None = Field(default=None, sa_column_kwargs={"nullable": True})
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
