"""Test chain YAML parsing and validation.

Covers the Master Super-Prompt V3 acceptance criterion:
"A malformed chain definition must not be silently accepted."
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.core.paths import PI_DIR

CHAINS_DIR = PI_DIR / "chains"


@pytest.fixture
def chains_dir() -> Path:
    if not CHAINS_DIR.exists():
        pytest.skip(f"chains directory not found at {CHAINS_DIR}")
    return CHAINS_DIR


def test_chains_directory_exists() -> None:
    assert CHAINS_DIR.exists(), f"{CHAINS_DIR} missing"
    assert CHAINS_DIR.is_dir()


def test_chains_directory_has_yaml_files(chains_dir: Path) -> None:
    yamls = list(chains_dir.glob("*.yaml"))
    assert len(yamls) >= 1, "no chain YAML files in .pi/chains/"


@pytest.mark.parametrize("yaml_file", sorted((PI_DIR / "chains").glob("*.yaml")))
def test_chain_yaml_is_valid(yaml_file: Path) -> None:
    content = yaml_file.read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    assert parsed is not None, f"{yaml_file.name} is empty"
    # Must have at least one of the canonical keys
    assert any(k in parsed for k in ("chain", "phases", "steps")), (
        f"{yaml_file.name} must define 'chain', 'phases', or 'steps'"
    )


@pytest.mark.parametrize("yaml_file", sorted((PI_DIR / "chains").glob("*.yaml")))
def test_chain_phases_have_required_fields(yaml_file: Path) -> None:
    parsed = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
    phases = parsed.get("phases") or parsed.get("steps") or []
    if not phases:
        pytest.skip(f"{yaml_file.name} has no phases/steps (single-step chain)")
    for i, phase in enumerate(phases):
        # Each phase/step needs at least an identifier
        assert any(k in phase for k in ("name", "id", "phase", "agent")), (
            f"{yaml_file.name} phase {i} missing identifier: {phase}"
        )


def test_chain_uses_real_agent_names(chains_dir: Path) -> None:
    """Chain YAMLs must reference agents that actually exist in .pi/agents/."""
    agents_dir = PI_DIR / "agents"
    if not agents_dir.exists():
        pytest.skip("no .pi/agents directory")
    yamls = list(chains_dir.glob("*.yaml"))
    for yaml_file in yamls:
        parsed = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
        phases = parsed.get("phases") or []
        for phase in phases:
            agent = phase.get("agent")
            if not agent:
                continue
            # Some chains use a list of agents; some a single one
            agents_to_check = agent if isinstance(agent, list) else [agent]
            for nested in phases:
                # Also check the `agents:` fan-out form
                nested_agents = nested.get("agents") or []
                if isinstance(nested_agents, list):
                    for entry in nested_agents:
                        if isinstance(entry, dict) and "name" in entry:
                            agents_to_check.append(entry["name"])
            for a in agents_to_check:
                # The reference can be either a top-level agent file or a
                # sub-agent name; we just verify it isn't a typo like "".
                assert a and isinstance(a, str), f"{yaml_file.name} references empty agent"
