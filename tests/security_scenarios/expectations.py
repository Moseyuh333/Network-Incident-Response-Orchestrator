"""Expectations + result data classes for the security scenario harness.

Kept separate from the runner so the same shapes can be reused by ad-hoc
scripts (e.g. "run just scenario s06 and dump its findings").
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class ScenarioCategory(str, enum.Enum):
    """What the scenario is trying to assert."""

    DETECT = "detect"  # N.I.R.O. SHOULD catch this
    FALSE_POSITIVE = "false_positive"  # N.I.R.O. SHOULD stay quiet
    KNOWN_GAP = "known_gap"  # N.I.R.O. CANNOT catch this (yet)


class Verdict(str, enum.Enum):
    """How the run actually went."""

    DETECTED = "detected"  # all expected findings present
    PARTIAL = "partial"  # some expected findings, some missing
    MISSED = "missed"  # no expected findings, but we expected some
    FALSE_POSITIVE = "false_positive"  # unexpected findings on a FP test
    CLEAN = "clean"  # FP test, no findings (the desired outcome)
    KNOWN_GAP = "known_gap"  # gap test, no findings, gap confirmed


@dataclass
class ScenarioExpectation:
    """The contract a scenario makes about what N.I.R.O. should detect."""

    id: str
    title: str
    category: ScenarioCategory
    expected_findings: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ScenarioResult:
    """One scenario's actual outcome, after running through the pipeline."""

    expectation: ScenarioExpectation
    events_ingested: int
    actual_findings: list[dict[str, Any]]
    verdict: Verdict
    matched: list[str]  # subset of expected_findings that were observed
    unexpected: list[str]  # findings observed that we didn't expect
    duration_seconds: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.expectation.id,
            "title": self.expectation.title,
            "category": self.expectation.category.value,
            "expected_findings": self.expectation.expected_findings,
            "actual_findings": [f.get("incident_type", "?") for f in self.actual_findings],
            "matched": self.matched,
            "unexpected": self.unexpected,
            "verdict": self.verdict.value,
            "events_ingested": self.events_ingested,
            "duration_seconds": round(self.duration_seconds, 3),
            "error": self.error,
            "notes": self.expectation.notes,
        }
