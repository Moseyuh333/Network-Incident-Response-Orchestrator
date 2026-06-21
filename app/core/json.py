"""JSON serialization utilities."""

from __future__ import annotations

import json
from typing import Any


def jsonable(value: Any) -> Any:
    """Return a JSON-safe copy of *value* (converts non-serializable types to str)."""
    if value is None:
        return None
    return json.loads(json.dumps(value, default=str))


__all__ = ["jsonable"]
