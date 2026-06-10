"""Validated runtime skill registry for Markdown and YAML frontmatter skills."""

from __future__ import annotations

import yaml
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
    max_tool_calls: int = Field(default=8, ge=0, le=20)
    safety_classification: str = "read_only"
    instructions: str = ""
    enabled: bool = True


class SkillRegistry:
    """Load, validate, and parse skills dynamically from .pi/skills/*/SKILL.md."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[dict[str, Any]]:
        results = []
        if not self.root.exists():
            return []
        
        # Check subdirectories
        for subdir in sorted(self.root.iterdir()):
            if subdir.is_dir():
                skill_md = subdir / "SKILL.md"
                if skill_md.exists():
                    results.append(self.validate(subdir.name))
        
        # Backward compatibility with old json files
        for json_file in sorted(self.root.glob("*.json")):
            results.append(self.validate_json_file(json_file))
            
        return results

    def validate(self, name: str) -> dict[str, Any]:
        """Validate a skill directory and parse its SKILL.md file."""
        subdir = self.root / name
        skill_md = subdir / "SKILL.md"
        
        if not skill_md.exists():
            # Check if name is a json file
            if name.endswith(".json") or (self.root / f"{name}.json").exists():
                json_path = self.root / name if name.endswith(".json") else self.root / f"{name}.json"
                return self.validate_json_file(json_path)
            return {"name": name, "valid": False, "manifest": None, "errors": ["SKILL.md file not found"]}

        try:
            content = skill_md.read_text(encoding="utf-8")
            parts = content.split("---", 2)
            if len(parts) < 3:
                return {"name": name, "valid": False, "manifest": None, "errors": ["Invalid frontmatter delimiters"]}
            
            frontmatter_raw = parts[1]
            instructions = parts[2].strip()
            
            metadata = yaml.safe_load(frontmatter_raw) or {}
            
            manifest_data = {
                "id": metadata.get("name") or name,
                "name": metadata.get("name") or name,
                "version": metadata.get("version") or "1.0.0",
                "description": metadata.get("description") or "",
                "triggers": metadata.get("triggers") or [],
                "allowed_tools": metadata.get("allowed_tools") or [
                    "get_incident", "list_related_events", "list_findings", "list_actions", "propose_response_action"
                ],
                "input_schema": metadata.get("input_schema") or {},
                "output_schema": metadata.get("output_schema") or {},
                "max_tool_calls": metadata.get("max_tool_calls") or 8,
                "safety_classification": metadata.get("safety") or "read_only",
                "instructions": instructions,
                "enabled": metadata.get("enabled", True)
            }
            
            manifest = SkillManifest.model_validate(manifest_data)
            return {"name": name, "valid": True, "manifest": manifest.model_dump(), "errors": []}
            
        except (ValidationError, yaml.YAMLError, ValueError, OSError) as exc:
            return {"name": name, "valid": False, "manifest": None, "errors": [str(exc)]}

    def validate_json_file(self, json_path: Path) -> dict[str, Any]:
        """Validate old format json files."""
        try:
            manifest = SkillManifest.model_validate_json(json_path.read_text(encoding="utf-8"))
            return {"name": json_path.name, "valid": True, "manifest": manifest.model_dump(), "errors": []}
        except (ValidationError, ValueError, OSError) as exc:
            return {"name": json_path.name, "valid": False, "manifest": None, "errors": [str(exc)]}

    def upsert(self, name: str, content: str) -> dict[str, Any]:
        """Write skill. For Markdown skills, we update name/SKILL.md."""
        subdir = self.root / name
        subdir.mkdir(parents=True, exist_ok=True)
        skill_md = subdir / "SKILL.md"
        skill_md.write_text(content, encoding="utf-8")
        return self.validate(name)

    def set_enabled(self, name: str, enabled: bool) -> dict[str, Any]:
        subdir = self.root / name
        skill_md = subdir / "SKILL.md"
        if not skill_md.exists():
            # Fallback to json if json exists
            json_path = self.root / f"{name}.json"
            if json_path.exists():
                import json
                data = json.loads(json_path.read_text(encoding="utf-8"))
                data["enabled"] = enabled
                json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                return self.validate_json_file(json_path)
            return {"name": name, "valid": False, "manifest": None, "errors": ["SKILL.md not found"]}

        content = skill_md.read_text(encoding="utf-8")
        parts = content.split("---", 2)
        if len(parts) >= 3:
            metadata = yaml.safe_load(parts[1]) or {}
            metadata["enabled"] = enabled
            new_frontmatter = yaml.dump(metadata, sort_keys=False).strip()
            new_content = f"---\n{new_frontmatter}\n---\n{parts[2]}"
            skill_md.write_text(new_content, encoding="utf-8")
            
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
