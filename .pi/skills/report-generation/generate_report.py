#!/usr/bin/env python3
"""Incident report generator script."""

from __future__ import annotations

import argparse
import json
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

        print(json.dumps({
            "incident_id": incident.id,
            "public_id": incident.public_id,
            "markdown_report": str(md_path),
            "json_report": str(json_path),
            "status": "success"
        }, indent=2))


if __name__ == "__main__":
    main()
