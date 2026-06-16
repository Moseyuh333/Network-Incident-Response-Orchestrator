"""Regression tests for the demo scenario loader.

The original ``scripts/load_demo.py`` iterated over the list returned by
``process_events`` and printed one success line per element. ``process_events``
returns the same incident once per correlated finding, so the port-scan
scenario (which produces 5+ findings for the same source) would emit the
success message 5 times in a row, drowning out the actual signal.

These tests pin the corrected behaviour: exactly one summary line per
scenario, and that line surfaces the correlated-finding count when relevant.
"""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlmodel import Session

from app.db.session import create_db_and_tables, engine
from app.schemas.event import EventCreate
from scripts import load_demo

REPO_ROOT = Path(__file__).resolve().parents[1]


def _make_port_scan_events() -> list[EventCreate]:
    now = datetime.now(timezone.utc)
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 445, 1433, 3306, 3389]
    return [
        EventCreate(
            external_event_id=f"regression-scan-{port}",
            timestamp=now - timedelta(seconds=(12 - i) * 5),
            sensor="sensor-internal-01",
            source_type="firewall",
            source_ip="198.51.100.250",  # unique IP for regression test
            destination_ip="10.10.20.250",
            source_port=49000 + i,
            destination_port=port,
            protocol="TCP",
            event_type="firewall",
            action="denied",
            severity="low",
        )
        for i, port in enumerate(ports)
    ]


def _cleanup_test_events() -> None:
    """Remove events created by these tests so repeated runs stay clean."""
    from sqlmodel import select
    from app.models.event import Event

    test_prefixes = ("regression-scan-", "regression-fp-")
    with Session(engine) as session:
        for prefix in test_prefixes:
            statement = select(Event).where(Event.external_event_id.startswith(prefix))
            for event in session.exec(statement).all():
                session.delete(event)
        session.commit()


@pytest.fixture
def clean_db() -> None:
    create_db_and_tables()
    _cleanup_test_events()
    yield
    _cleanup_test_events()


def test_load_demo_prints_single_success_message_per_scenario(monkeypatch, clean_db) -> None:
    """One scenario load must produce exactly one '[+] Loaded scenario' line.

    The bug: ``for inc in incidents: print(...)`` printed the same incident
    multiple times. We assert exactly one summary line and that it contains
    the new "from N correlated findings" suffix.
    """
    monkeypatch.setattr(sys, "argv", ["load_demo.py", "--scenario", "port-scan"])
    monkeypatch.setattr(load_demo, "load_port_scan", lambda _session: _make_port_scan_events())

    buf = io.StringIO()
    with redirect_stdout(buf):
        load_demo.main()

    output = buf.getvalue()
    success_lines = [line for line in output.splitlines() if line.startswith("[+] Loaded scenario")]

    assert len(success_lines) == 1, f"expected 1 success line, got {len(success_lines)}:\n{output}"
    assert "port-scan" in success_lines[0]
    # When multiple findings correlate to the same incident the loader must
    # surface the count so the operator can tell correlation happened.
    assert "correlated findings" in success_lines[0]


def test_load_demo_fp_scenario_prints_zero_incident_message(monkeypatch, clean_db) -> None:
    """False-positive scenario: no incident should be created and the loader
    must print the '0 incidents triggered' message rather than crash on the
    empty ``incidents`` list."""
    monkeypatch.setattr(sys, "argv", ["load_demo.py", "--scenario", "false-positive"])
    monkeypatch.setattr(
        load_demo,
        "load_false_positive",
        lambda _session: [
            EventCreate(
                external_event_id=f"regression-fp-{i}",
                timestamp=datetime.now(timezone.utc),
                sensor="sensor-internal-01",
                source_type="firewall",
                source_ip="10.0.0.99",  # approved scanner IP
                destination_ip="10.0.0.6",
                source_port=48000 + i,
                destination_port=p,
                protocol="TCP",
                event_type="firewall",
                action="denied",
                severity="low",
            )
            for i, p in enumerate([21, 22, 80, 443])
        ],
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        load_demo.main()

    output = buf.getvalue()
    assert "0 incidents triggered" in output
    assert "false-positive" in output
    # And critically: the new code path must NOT crash with IndexError or
    # produce multiple lines for the same scenario.
    assert output.count("[+] Loaded scenario") == 1
