#!/usr/bin/env python3
"""Incident report generator script.

Produces four artefacts from one incident:

1. ``<public_id>.json``  — machine-readable structured payload
2. ``<public_id>.md``    — Markdown narrative (source of truth)
3. ``<public_id>.txt``   — plain-text rendering of the Markdown (log-friendly)
4. ``<public_id>.docx``  — Microsoft Word document rendered via python-docx

The docx output is best-effort: if ``python-docx`` is not installed we fall
back to the three text formats and emit a non-fatal warning to stderr so the
agent loop can still surface the report. The other three formats are always
written.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable

from sqlmodel import select

from app.core.paths import REPORT_DIR
from app.db.session import SessionLocal
from app.models.incident import AuditEntry, Finding, Incident, ResponseAction


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-id", required=True, type=int)
    args = parser.parse_args()

    with SessionLocal() as session:
        incident = session.get(Incident, args.incident_id)
        if not incident:
            print(json.dumps({"error": f"Incident {args.incident_id} not found"}))
            return

        findings = session.exec(
            select(Finding).where(Finding.incident_id == incident.id)
        ).all()

        actions = session.exec(
            select(ResponseAction).where(ResponseAction.incident_id == incident.id)
        ).all()

        audits = session.exec(
            select(AuditEntry)
            .where(AuditEntry.target_type == "incident")
            .where(AuditEntry.target_id == incident.public_id)
        ).all()

        # Build JSON report
        report_data = {
            "incident_id": incident.id,
            "public_id": incident.public_id,
            "title": incident.title,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "status": incident.status,
            "source_ip": incident.source_ip,
            "destination_ip": incident.destination_ip,
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            "summary": incident.llm_summary or incident.summary or "No summary",
            "mitre_mapping": incident.mitre_mapping or [],
            "findings": [
                {
                    "detector_id": f.detector_id,
                    "incident_type": f.incident_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence": f.evidence_summary,
                }
                for f in findings
            ],
            "actions": [
                {
                    "id": a.id,
                    "action_type": a.action_type,
                    "status": a.status,
                    "risk": a.risk,
                    "result": a.result,
                    "verification": a.verification_result,
                }
                for a in actions
            ],
            "timeline": [
                {
                    "timestamp": audit.timestamp.isoformat() if audit.timestamp else None,
                    "actor": audit.actor,
                    "action": audit.action,
                    "before": audit.before_state,
                    "after": audit.after_state,
                }
                for audit in audits
            ]
        }

        # Write reports
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        json_path = REPORT_DIR / f"{incident.public_id}.json"
        md_path = REPORT_DIR / f"{incident.public_id}.md"

        json_path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")

        # Generate markdown report
        lines = [
            f"# Incident Report: {incident.public_id}",
            "",
            f"**Title**: {incident.title}",
            f"**Classification**: {incident.incident_type}",
            f"**Severity**: {incident.severity}",
            f"**Confidence**: {incident.confidence}",
            f"**Status**: {incident.status}",
            "",
            "## Summary",
            incident.llm_summary or incident.summary or "No detailed analysis available.",
            "",
            "## Network Scopes",
            f"- Source IP: `{incident.source_ip}`",
            f"- Destination IP: `{incident.destination_ip}`",
            "",
            "## MITRE ATT&CK Mappings",
        ]
        for m in (incident.mitre_mapping or []):
            lines.append(f"- **{m.get('tactic', 'Unknown')}**: {m.get('technique_id', '')} - {m.get('technique_name', '')}")
        
        lines.extend([
            "",
            "## Findings & Evidence",
        ])
        for f in findings:
            lines.append(f"### {f.incident_type} ({f.severity})")
            lines.append(f"- **Detector**: `{f.detector_id}`")
            lines.append(f"- **Evidence**: {f.evidence_summary}")
            lines.append("")

        lines.extend([
            "## Containment & Response Actions",
        ])
        for a in actions:
            lines.append(f"### Action: `{a.action_type}` (State: {a.status})")
            lines.append(f"- **Risk level**: `{a.risk}`")
            lines.append(f"- **Simulated**: `{a.simulated}`")
            if a.result:
                lines.append(f"- **Result**: {json.dumps(a.result)}")
            if a.verification_result:
                lines.append(f"- **Verification**: {json.dumps(a.verification_result)}")
            lines.append("")

        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Plain-text rendering of the Markdown (log-friendly, no formatting).
        # Strips the most common Markdown markers so the .txt is readable
        # in `tail`, `less`, or a SIEM log viewer.
        txt_path = REPORT_DIR / f"{incident.public_id}.txt"
        txt_path.write_text(_markdown_to_text(lines), encoding="utf-8")

        # Microsoft Word document. Best-effort: if python-docx is missing
        # we keep the three text formats and warn instead of failing the
        # whole skill — the agent loop has higher-priority work to do.
        docx_path = REPORT_DIR / f"{incident.public_id}.docx"
        docx_error: str | None = None
        try:
            snapshot = _snapshot(incident, findings, actions, audits)
            _write_docx(docx_path, snapshot)
        except ImportError as exc:
            docx_error = f"python-docx not installed: {exc}"
            print(f"[!] {docx_error} — skipping {docx_path.name}", file=sys.stderr)
        except Exception as exc:  # pragma: no cover - writer failures vary
            docx_error = f"docx writer failed: {exc}"
            print(f"[!] {docx_error}", file=sys.stderr)

        result_payload: dict[str, object] = {
            "incident_id": incident.id,
            "public_id": incident.public_id,
            "markdown_report": str(md_path),
            "json_report": str(json_path),
            "text_report": str(txt_path),
            "docx_report": str(docx_path) if docx_error is None else None,
            "status": "success",
        }
        if docx_error is not None:
            result_payload["docx_error"] = docx_error
        print(json.dumps(result_payload, indent=2))


# ── Output-format helpers ────────────────────────────────────────────
# Kept module-level so tests can call them directly without re-invoking
# the agent skill entry point.

# Strip the most common Markdown markers so the .txt version stays
# readable in plain-text viewers (SIEM, `less`, `tail -f`).
_MD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^#{1,6}\s+"), ""),                # headings
    (re.compile(r"\*\*(.+?)\*\*"), r"\1"),           # bold
    (re.compile(r"\*(.+?)\*"), r"\1"),               # italic
    (re.compile(r"`([^`]+)`"), r"\1"),               # inline code
    (re.compile(r"^\s*[-*]\s+"), "  - "),            # bullet markers (normalize)
)


def _markdown_to_text(lines: Iterable[str]) -> str:
    """Render a list of Markdown lines as plain text."""
    out: list[str] = []
    for raw in lines:
        line = raw
        for pattern, replacement in _MD_PATTERNS:
            line = pattern.sub(replacement, line)
        out.append(line)
    # Collapse runs of >2 blank lines to a single blank line.
    rendered = "\n".join(out) + "\n"
    rendered = re.sub(r"\n{3,}", "\n\n", rendered)
    return rendered


def _snapshot(
    incident: Incident,
    findings: list[Finding],
    actions: list[ResponseAction],
    audits: list[AuditEntry],
) -> dict[str, object]:
    """Materialise one incident into a plain-dict snapshot.

    Built while the SQLAlchemy session is still open so all attribute
    access succeeds. The result is a self-contained dict that can be
    passed across the session boundary — useful for ``_write_docx``
    (which renders after the MD/JSON/TXT writers finish) and for tests
    that need to feed real DB data without keeping a session alive.
    """
    return {
        "incident": {
            "id": incident.id,
            "public_id": incident.public_id,
            "title": incident.title,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "confidence": incident.confidence,
            "status": incident.status,
            "source_ip": incident.source_ip,
            "destination_ip": incident.destination_ip,
            "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
            "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            "summary": incident.summary,
            "llm_summary": incident.llm_summary,
            "mitre_mapping": list(incident.mitre_mapping or []),
            "recommended_actions": list(incident.recommended_actions or []),
        },
        "findings": [
            {
                "id": f.id,
                "detector_id": f.detector_id,
                "incident_type": f.incident_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence_summary": f.evidence_summary,
            }
            for f in findings
        ],
        "actions": [
            {
                "id": a.id,
                "action_type": a.action_type,
                "status": a.status,
                "risk": a.risk,
                "simulated": bool(a.simulated),
                "result": a.result,
                "verification_result": a.verification_result,
            }
            for a in actions
        ],
        "audits": [
            {
                "timestamp": audit.timestamp.isoformat() if audit.timestamp else None,
                "actor": audit.actor,
                "action": audit.action,
                "before": audit.before_state,
                "after": audit.after_state,
            }
            for audit in audits
        ],
    }


def _write_docx(path: Path, snapshot: dict[str, object]) -> None:
    """Render the snapshot as a Word .docx file.

    Lazy-imports ``docx`` so the rest of the script can run on hosts
    that don't have python-docx installed (CI, minimal containers).
    Accepts a snapshot dict (not live ORM objects) so it stays pure and
    works with data the test suite produces from a real DB session.
    """
    from docx import Document  # python-docx
    from docx.shared import Pt

    incident = snapshot["incident"]  # type: ignore[index]
    findings = snapshot["findings"]  # type: ignore[assignment]
    actions = snapshot["actions"]  # type: ignore[assignment]
    audits = snapshot["audits"]  # type: ignore[assignment]

    document = Document()
    title = document.add_heading(f"Incident Report: {incident['public_id']}", level=0)
    for run in title.runs:
        run.font.size = Pt(18)

    # Metadata block
    meta = document.add_paragraph()
    meta.add_run("Title: ").bold = True
    meta.add_run(f"{incident['title']}\n")
    meta.add_run("Classification: ").bold = True
    meta.add_run(f"{incident['incident_type']}\n")
    meta.add_run("Severity: ").bold = True
    meta.add_run(f"{incident['severity']}\n")
    meta.add_run("Confidence: ").bold = True
    meta.add_run(f"{incident['confidence']}\n")
    meta.add_run("Status: ").bold = True
    meta.add_run(f"{incident['status']}")

    document.add_heading("Summary", level=1)
    document.add_paragraph(
        incident.get("llm_summary") or incident.get("summary") or "No detailed analysis available."  # type: ignore[union-attr]
    )

    document.add_heading("Network Scopes", level=1)
    document.add_paragraph(f"Source IP: {incident['source_ip']}", style="List Bullet")
    document.add_paragraph(f"Destination IP: {incident['destination_ip']}", style="List Bullet")

    document.add_heading("MITRE ATT&CK Mappings", level=1)
    for m in (incident.get("mitre_mapping") or []):  # type: ignore[union-attr]
        document.add_paragraph(
            f"{m.get('tactic', 'Unknown')}: "
            f"{m.get('technique_id', '')} - {m.get('technique_name', '')}",
            style="List Bullet",
        )

    document.add_heading("Findings & Evidence", level=1)
    for f in findings:  # type: ignore[assignment]
        document.add_heading(f"{f['incident_type']} ({f['severity']})", level=2)
        p = document.add_paragraph()
        p.add_run("Detector: ").bold = True
        p.add_run(str(f["detector_id"]))
        p = document.add_paragraph()
        p.add_run("Evidence: ").bold = True
        p.add_run(f.get("evidence_summary") or "")  # type: ignore[union-attr]

    document.add_heading("Containment & Response Actions", level=1)
    for a in actions:  # type: ignore[assignment]
        document.add_heading(f"Action: {a['action_type']} (State: {a['status']})", level=2)
        p = document.add_paragraph()
        p.add_run("Risk level: ").bold = True
        p.add_run(str(a.get("risk") or "unknown"))
        p = document.add_paragraph()
        p.add_run("Simulated: ").bold = True
        p.add_run(str(a.get("simulated")))
        if a.get("result"):
            p = document.add_paragraph()
            p.add_run("Result: ").bold = True
            p.add_run(json.dumps(a["result"]))
        if a.get("verification_result"):
            p = document.add_paragraph()
            p.add_run("Verification: ").bold = True
            p.add_run(json.dumps(a["verification_result"]))

    document.add_heading("Timeline", level=1)
    for audit in audits:  # type: ignore[assignment]
        document.add_paragraph(
            f"[{audit.get('timestamp') or '?'}] "
            f"{audit.get('actor') or '?'} :: {audit.get('action') or '?'}",
            style="List Bullet",
        )

    document.save(str(path))


if __name__ == "__main__":
    main()