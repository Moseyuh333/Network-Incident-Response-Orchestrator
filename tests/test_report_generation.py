"""Tests for the ``.pi/skills/report-generation`` skill.

The skill is a small standalone script invoked by the Pi agent runtime
after an incident is triaged. These tests pin two behaviours:

1. Every invocation produces four artefacts (``<id>.md``, ``<id>.json``,
   ``<id>.txt``, ``<id>.docx``) when python-docx is installed.
2. ``.docx`` is best-effort — if python-docx is missing the other three
   formats still come out and the script reports the failure in its JSON
   result payload instead of crashing the agent loop.

We call the module-level helpers directly to avoid spawning the script as
a subprocess; the helpers are the ones the agent runtime actually uses.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_PATH = REPO_ROOT / ".pi" / "skills" / "report-generation" / "generate_report.py"


def _load_skill_module():
    """Import the skill script as a module under a unique name."""
    spec = importlib.util.spec_from_file_location("report_generation_skill", SKILL_PATH)
    assert spec is not None and spec.loader is not None, "could not load skill spec"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def skill_module():
    """Cache the imported skill across tests in this module."""
    return _load_skill_module()


# ── Pure helper tests (no DB, no filesystem state) ───────────────────


def test_markdown_to_text_strips_common_markers(skill_module) -> None:
    src = [
        "# Title",
        "",
        "## Findings & Evidence",
        "",
        "- **Severity**: `high`",
        "- normal bullet",
        "",
        "",
    ]
    out = skill_module._markdown_to_text(src)
    assert "Title" in out
    assert "Findings & Evidence" in out
    # Bold markers removed.
    assert "**" not in out
    # Inline code markers removed.
    assert "`" not in out
    # Bullet markers normalized.
    assert "  - Severity: high" in out
    # Excessive blank lines collapsed.
    assert "\n\n\n" not in out


# ── Full pipeline tests (real DB + filesystem) ───────────────────────


def _persist_incident(skill_module, session, tmp_path: Path, *, public_id: str = "INC-TEST-REPORT"):
    """Insert one minimal incident + one finding + one action + one audit.

    Returns the same dict shape the skill itself builds via
    ``_snapshot()`` so the test exercises the real codepath (snapshot
    first, then renderer) with real DB rows — no hardcoded data.
    """
    from app.db.session import create_db_and_tables
    from app.models.incident import AuditEntry, Finding, Incident, ResponseAction

    create_db_and_tables()
    now = datetime.now(timezone.utc)
    # SQLAlchemy 2.x expires every attribute on commit by default. Keep
    # rows live so the test can read them after each commit without
    # triggering a re-load that would detach the instance.
    session.expire_on_commit = False

    incident = Incident(
        public_id=public_id,
        title="Regression: report docx+txt",
        incident_type="brute_force",
        severity="high",
        confidence=0.9,
        status="open",
        source_ip="203.0.113.10",
        destination_ip="10.10.20.10",
        first_seen=now,
        last_seen=now,
        summary="Regression incident for report skill.",
        llm_summary="LLM triaged as brute force from single source.",
        mitre_mapping=[
            {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force"},
        ],
        recommended_actions=["simulate_block_ip"],
    )
    session.add(incident)
    session.commit()
    session.refresh(incident)

    finding = Finding(
        incident_id=incident.id,
        detector_id="regression-detector",
        incident_type="brute_force",
        severity="high",
        confidence=0.9,
        evidence_summary="12 failed SSH attempts in 30s.",
    )
    session.add(finding)

    action = ResponseAction(
        incident_id=incident.id,
        action_type="simulate_block_ip",
        status="proposed",
        risk="low",
        simulated=True,
        result={"actor": "system"},
        verification_result={"status": "ok"},
    )
    session.add(action)
    session.commit()

    audit = AuditEntry(
        target_type="incident",
        target_id=incident.public_id,
        actor="test",
        action="incident_created",
        before_state=None,
        after_state={"status": "open"},
        timestamp=now,
    )
    session.add(audit)
    session.commit()
    session.refresh(incident)
    return skill_module._snapshot(incident, [finding], [action], [audit])


def test_full_skill_produces_md_json_txt_and_docx(skill_module, monkeypatch, tmp_path) -> None:
    """Happy path: python-docx installed → all four artefacts appear."""
    from sqlmodel import Session

    from app.core import paths as core_paths
    from app.db.session import engine

    # Redirect REPORT_DIR so we don't pollute the real `.pi/reports/` tree.
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    monkeypatch.setattr(core_paths, "REPORT_DIR", reports_dir, raising=False)
    # The skill module imported REPORT_DIR at import time; patch the bound
    # reference inside the loaded module so main() sees the new path.
    monkeypatch.setattr(skill_module, "REPORT_DIR", reports_dir)

    # Ensure SessionLocal closes to the test DB so the inserted row is visible.
    from app.db import session as db_session
    monkeypatch.setattr(db_session, "engine", engine, raising=False)
    monkeypatch.setattr(db_session, "SessionLocal", lambda: Session(engine), raising=False)

    from sqlmodel import delete
    from app.models.incident import Incident
    with Session(engine) as session:
        session.exec(delete(Incident).where(Incident.public_id == "INC-TEST-REPORT"))
        session.commit()
        _persist_incident(skill_module, session, tmp_path)

    try:
        from sqlmodel import select
        with Session(engine) as session:
            incident_id = session.exec(
                select(Incident.id).where(Incident.public_id == "INC-TEST-REPORT")
            ).first()
        # Drive the skill's argparse path with the real incident ID we
        # just inserted — same flag the operator would type on the CLI.
        monkeypatch.setattr(sys, "argv", ["generate_report.py", "--incident-id", str(incident_id)])
        skill_module.main()
    finally:
        # clean up
        from sqlmodel import delete as _delete
        with Session(engine) as session:
            session.exec(_delete(Incident).where(Incident.public_id == "INC-TEST-REPORT"))
            session.commit()

    # md + json + txt always present
    assert (reports_dir / "INC-TEST-REPORT.md").exists()
    assert (reports_dir / "INC-TEST-REPORT.json").exists()
    assert (reports_dir / "INC-TEST-REPORT.txt").exists()

    md = (reports_dir / "INC-TEST-REPORT.md").read_text(encoding="utf-8")
    assert "Incident Report: INC-TEST-REPORT" in md

    payload = json.loads((reports_dir / "INC-TEST-REPORT.json").read_text(encoding="utf-8"))
    assert payload["public_id"] == "INC-TEST-REPORT"
    assert payload["mitre_mapping"][0]["technique_id"] == "T1110"

    txt = (reports_dir / "INC-TEST-REPORT.txt").read_text(encoding="utf-8")
    # Plain-text rendering must NOT carry Markdown bold markers.
    assert "**" not in txt
    # But must carry the incident summary text.
    assert "LLM triaged as brute force" in txt

    # docx: skipped if python-docx missing; otherwise the file is a real ZIP.
    docx_path = reports_dir / "INC-TEST-REPORT.docx"
    if importlib.util.find_spec("docx") is not None:
        assert docx_path.exists(), "docx file missing even though python-docx is installed"
        with docx_path.open("rb") as fh:
            assert fh.read(2) == b"PK", "docx file is not a valid zip container"
    else:
        # Degraded mode: file absent, but main() did not raise.
        assert not docx_path.exists()


def test_docx_writer_emits_zip_container(skill_module, tmp_path) -> None:
    """Direct test of ``_write_docx`` — verifies the .docx writer path."""
    docx_spec = importlib.util.find_spec("docx")
    if docx_spec is None:
        pytest.skip("python-docx not installed in this environment")

    from datetime import datetime, timezone
    from sqlmodel import Session

    from app.db.session import engine
    from app.models.incident import AuditEntry, Finding, Incident, ResponseAction

    # build a transient incident in the test DB
    from sqlmodel import delete
    with Session(engine) as session:
        session.exec(delete(Incident).where(Incident.public_id == "INC-TEST-DOCX"))
        session.commit()
        session.expire_on_commit = False
        now = datetime.now(timezone.utc)
        inc = Incident(
            public_id="INC-TEST-DOCX",
            title="docx-only test",
            incident_type="port_scan",
            severity="low",
            confidence=0.7,
            status="closed",
            source_ip="203.0.113.20",
            destination_ip="10.10.20.20",
            first_seen=now,
            last_seen=now,
            summary="s",
            llm_summary="LLM body",
            mitre_mapping=[],
            recommended_actions=[],
        )
        session.add(inc)
        session.commit()
        session.refresh(inc)
        finding = Finding(
            incident_id=inc.id, detector_id="d", incident_type="port_scan",
            severity="low", confidence=0.5, evidence_summary="e",
        )
        action = ResponseAction(
            incident_id=inc.id, action_type="simulate_notify_admin",
            status="completed", risk="low", simulated=True,
        )
        audit = AuditEntry(
            target_type="incident", target_id=inc.public_id, actor="test",
            action="closed", before_state={}, after_state={}, timestamp=now,
        )
        session.add_all([finding, action, audit])
        session.commit()

    try:
        # Build the snapshot INSIDE the ``with`` block so attribute
        # access works against an attached ORM instance. After the
        # block exits, the snapshot is plain data — no session needed.
        snapshot = skill_module._snapshot(inc, [finding], [action], [audit])
        out_path = tmp_path / "out.docx"
        skill_module._write_docx(out_path, snapshot)
        assert out_path.exists()
        with out_path.open("rb") as fh:
            assert fh.read(2) == b"PK", "docx is not a valid zip container"
    finally:
        from sqlmodel import delete as _delete
        with Session(engine) as session:
            session.exec(_delete(Incident).where(Incident.public_id == "INC-TEST-DOCX"))
            session.commit()
