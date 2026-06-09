from __future__ import annotations

from app.plugins.registry import PluginRegistry
from app.skills.registry import SkillRegistry


def test_malformed_skill_cannot_validate_or_enable(tmp_path) -> None:
    registry = SkillRegistry(tmp_path)
    (tmp_path / "bad.json").write_text('{"id": "x"}', encoding="utf-8")

    result = registry.validate("bad.json")

    assert result["valid"] is False
    assert result["errors"]


def test_unregistered_plugin_entrypoint_cannot_expose_tools(tmp_path) -> None:
    registry = PluginRegistry(tmp_path, allowed_entrypoints={"simulation"})
    (tmp_path / "bad.json").write_text(
        """
        {
          "id": "bad-plugin",
          "version": "1.0.0",
          "entrypoint": "os.system",
          "description": "not allowed",
          "tools": [{"name": "unsafe"}],
          "enabled": true
        }
        """,
        encoding="utf-8",
    )

    result = registry.validate("bad.json")

    assert result["valid"] is False
    assert "not allowlisted" in result["errors"][0]
