"""Response action schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ResponseActionResponse(BaseModel):
    """Schema returned for a response action."""

    id: int
    incident_id: int
    action_type: str
    status: str
    simulated: bool
    requires_approval: bool
    result: dict[str, Any] | None
    created_at: datetime

    model_config = {"from_attributes": True}
