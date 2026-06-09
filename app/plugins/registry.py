"""Validated runtime plugin registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class PluginToolManifest(BaseModel):
    name: str
    risk_level: str = "read_only"
    approval_required: bool = False
    reversible: bool = True


class PluginManifest(BaseModel):
    id: str = Field(..., min_length=3)
    version: str = "1.0.0"
    entrypoint: str
    description: str
    tools: list[PluginToolManifest] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    required_configuration: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = False


class PluginRegistry:
    """Load and validate local plugin manifests without importing arbitrary code."""

    def __init__(self, root: Path, allowed_entrypoints: set[str] | None = None) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.allowed_entrypoints = allowed_entrypoints or {"simulation"}

    def list(self) -> list[dict[str, Any]]:
        return [self.validate(path.name) for path in sorted(self.root.glob("*.json"))]

    def validate(self, name: str) -> dict[str, Any]:
        path = self._path(name)
        try:
            manifest = PluginManifest.model_validate_json(path.read_text(encoding="utf-8"))
            errors = []
            if manifest.entrypoint not in self.allowed_entrypoints:
                errors.append(f"entrypoint {manifest.entrypoint!r} is not allowlisted")
            return {
                "name": name,
                "valid": not errors,
                "manifest": manifest.model_dump(),
                "errors": errors,
            }
        except (ValidationError, ValueError, OSError) as exc:
            return {"name": name, "valid": False, "manifest": None, "errors": [str(exc)]}

    def upsert(self, name: str, content: str) -> dict[str, Any]:
        path = self._path(name)
        json.loads(content)
        path.write_text(content, encoding="utf-8")
        return self.validate(name)

    def set_enabled(self, name: str, enabled: bool) -> dict[str, Any]:
        validation = self.validate(name)
        if not validation["valid"]:
            return validation
        path = self._path(name)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["enabled"] = enabled
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return self.validate(name)

    def _path(self, name: str) -> Path:
        safe = Path(name).name
        if safe != name or not safe.endswith(".json"):
            raise ValueError("plugin manifest name must be a local .json file")
        return self.root / safe
