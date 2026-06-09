"""Validated runtime skill registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class SkillManifest(BaseModel):
    id: str = Field(..., min_length=3)
    name: str
    version: str = "1.0.0"
    description: str
    triggers: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    max_tool_calls: int = Field(default=5, ge=0, le=20)
    safety_classification: str = "read_only"
    instructions: str
    enabled: bool = True


class SkillRegistry:
    """Load and validate local skill manifests."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[dict[str, Any]]:
        return [self.validate(path.name) for path in sorted(self.root.glob("*.json"))]

    def validate(self, name: str) -> dict[str, Any]:
        path = self._path(name)
        try:
            manifest = SkillManifest.model_validate_json(path.read_text(encoding="utf-8"))
            return {"name": name, "valid": True, "manifest": manifest.model_dump(), "errors": []}
        except (ValidationError, ValueError, OSError) as exc:
            return {"name": name, "valid": False, "manifest": None, "errors": [str(exc)]}

    def upsert(self, name: str, content: str) -> dict[str, Any]:
        path = self._path(name)
        json.loads(content)
        path.write_text(content, encoding="utf-8")
        return self.validate(name)

    def set_enabled(self, name: str, enabled: bool) -> dict[str, Any]:
        path = self._path(name)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["enabled"] = enabled
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return self.validate(name)

    def select(self, task: str, incident_type: str | None = None) -> SkillManifest | None:
        candidates: list[SkillManifest] = []
        text = f"{task} {incident_type or ''}".lower()
        for item in self.list():
            if not item["valid"]:
                continue
            manifest = SkillManifest.model_validate(item["manifest"])
            if not manifest.enabled:
                continue
            if any(trigger.lower() in text for trigger in manifest.triggers):
                candidates.append(manifest)
        return candidates[0] if candidates else None

    def _path(self, name: str) -> Path:
        safe = Path(name).name
        if safe != name or not safe.endswith(".json"):
            raise ValueError("skill manifest name must be a local .json file")
        return self.root / safe
