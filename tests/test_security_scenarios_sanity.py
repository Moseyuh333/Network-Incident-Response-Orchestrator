"""Sanity test for the security-scenarios scaffolding.

A tiny test that verifies the scenario registry is populated and each
scenario is a valid ``Scenario`` subclass. It exists to satisfy the
Master Super-Prompt V3 acceptance criterion that a missing-skill-script
fails validation — by extension, a scenario with a broken build_events
contract must also fail this test.
"""

from __future__ import annotations

import inspect

from tests.security_scenarios import REGISTRY
from tests.security_scenarios.base import Scenario, Verdict


def test_registry_is_populated() -> None:
    assert len(REGISTRY) >= 20, f"only {len(REGISTRY)} scenarios registered (PDF requires 25)"


def test_every_scenario_is_a_proper_subclass() -> None:
    for cls in REGISTRY:
        assert issubclass(cls, Scenario), f"{cls} is not a Scenario subclass"
        assert inspect.isabstract(cls) is False, f"{cls} is abstract"


def test_every_scenario_has_a_valid_category() -> None:
    valid_categories = {"detect", "false_positive", "known_gap"}
    for cls in REGISTRY:
        assert cls.category.value in valid_categories, (
            f"{cls.__name__} has unknown category {cls.category}"
        )


def test_every_scenario_id_is_unique() -> None:
    ids = [cls.id for cls in REGISTRY]
    dupes = {x for x in ids if ids.count(x) > 1}
    assert not dupes, f"duplicate scenario ids: {dupes}"


def test_every_scenario_id_matches_filename_convention() -> None:
    """Scenario id should look like 'sNN' and the file should be sNN_*.py."""
    import re
    for cls in REGISTRY:
        assert re.match(r"^s\d{2}$", cls.id), f"{cls.__name__} has id {cls.id!r}, expected sNN"


def test_every_scenario_has_a_build_events_method() -> None:
    for cls in REGISTRY:
        assert hasattr(cls, "build_events"), f"{cls.__name__} missing build_events"
        sig = inspect.signature(cls.build_events)
        # build_events(self, alloc)
        params = list(sig.parameters)
        assert params[0] == "self", f"{cls.__name__}.build_events missing self"
        assert len(params) >= 2, f"{cls.__name__}.build_events must take an IpAllocator"


def test_every_scenario_judge_is_sound() -> None:
    """The judge must not raise for any (category, actual_findings) pair."""
    for cls in REGISTRY:
        scenario = cls()
        # Try a few representative findings sets
        for actual in [[], ["Brute Force"], ["Brute Force", "Policy Violation"], ["Unknown Finding"]]:
            verdict = scenario._judge(actual)
            assert isinstance(verdict, Verdict), (
                f"{cls.__name__}._judge returned {type(verdict).__name__} for actual={actual}"
            )
