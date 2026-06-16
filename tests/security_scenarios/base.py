"""Base class for security scenarios.

Each scenario is a self-contained unit: it builds a list of events, runs
them through the real ingestion pipeline, then compares the findings
against an expectation. The runner in `run_all.py` iterates the registry
and prints a coverage report.
"""

from __future__ import annotations

import abc
import logging
import time

from sqlmodel import Session, select

from app.db.session import create_db_and_tables, engine
from app.models.event import Event
from app.schemas.event import EventCreate
from app.services.ingestion import ingest_event, process_events

from .expectations import (
    ScenarioCategory,
    ScenarioExpectation,
    ScenarioResult,
    Verdict,
)
from .helpers import IpAllocator

# Quiet down the niro logger so the test report stays readable.
logging.getLogger("niro").setLevel(logging.ERROR)


class Scenario(abc.ABC):
    """Subclass this for every attack pattern you want to test."""

    id: str = ""
    title: str = ""
    category: ScenarioCategory = ScenarioCategory.DETECT
    expected_findings: list[str] = []
    notes: str = ""

    def __init__(self) -> None:
        self.expectation = ScenarioExpectation(
            id=self.id,
            title=self.title,
            category=self.category,
            expected_findings=list(self.expected_findings),
            notes=self.notes,
        )

    @abc.abstractmethod
    def build_events(self, alloc: IpAllocator) -> list[EventCreate]:
        """Return the synthetic events that represent this attack."""

    def _external_ids(self, events: list[EventCreate]) -> list[str]:
        return [e.external_event_id for e in events if e.external_event_id]

    def _cleanup(self, external_ids: list[str]) -> None:
        if not external_ids:
            return
        with Session(engine) as session:
            statement = select(Event).where(Event.external_event_id.in_(external_ids))
            for event in session.exec(statement).all():
                session.delete(event)
            session.commit()

    def run(self) -> ScenarioResult:
        """Run the scenario end-to-end and return a result.

        Always cleans up after itself, even on failure, so reruns are
        deterministic.
        """
        create_db_and_tables()
        alloc = IpAllocator(self.id)
        external_ids: list[str] = []
        started = time.monotonic()
        try:
            raw_events = self.build_events(alloc)
            external_ids = self._external_ids(raw_events)
            self._cleanup(external_ids)  # ensure idempotent reruns

            with Session(engine) as session:
                persisted = [ingest_event(session, e) for e in raw_events]
                findings = process_events(session, persisted)
                # Materialise the data we need BEFORE the session closes —
                # otherwise SQLAlchemy raises DetachedInstanceError when we
                # try to read ``finding.incident_type`` later.
                actual_types = [f.incident_type for f in findings]
                session.commit()
        except Exception as exc:
            self._cleanup(external_ids)
            return ScenarioResult(
                expectation=self.expectation,
                events_ingested=0,
                actual_findings=[],
                verdict=Verdict.MISSED,
                matched=[],
                unexpected=[],
                duration_seconds=time.monotonic() - started,
                error=f"{type(exc).__name__}: {exc}",
            )

        self._cleanup(external_ids)

        verdict = self._judge(actual_types)
        matched = [t for t in self.expected_findings if t in actual_types]
        unexpected = [t for t in actual_types if t not in self.expected_findings]

        return ScenarioResult(
            expectation=self.expectation,
            events_ingested=len(raw_events),
            actual_findings=[{"incident_type": t} for t in actual_types],
            verdict=verdict,
            matched=matched,
            unexpected=unexpected,
            duration_seconds=time.monotonic() - started,
        )

    def _judge(self, actual: list[str]) -> Verdict:
        """Map the actual findings to a verdict based on the category."""
        if self.category is ScenarioCategory.FALSE_POSITIVE:
            if actual:
                return Verdict.FALSE_POSITIVE
            return Verdict.CLEAN

        if self.category is ScenarioCategory.KNOWN_GAP:
            if actual:
                # ML happened to flag it — that's a bonus, not a failure.
                return Verdict.PARTIAL
            return Verdict.KNOWN_GAP

        # DETECT category: did we see all expected findings?
        missing = [t for t in self.expected_findings if t not in actual]
        if not missing and actual:
            return Verdict.DETECTED
        if any(t in actual for t in self.expected_findings):
            return Verdict.PARTIAL
        return Verdict.MISSED


# ── Registry ────────────────────────────────────────────────────────────
# The runner imports this and iterates the subclasses. We populate it
# via the metaclass in registry.py.

REGISTRY: list[type[Scenario]] = []


def register(cls: type[Scenario]) -> type[Scenario]:
    """Class decorator that adds a Scenario to the global registry."""
    REGISTRY.append(cls)
    return cls
