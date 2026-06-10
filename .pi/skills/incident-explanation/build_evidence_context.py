#!/usr/bin/env python3
"""Incident context builder script."""

from __future__ import annotations

import argparse
import json
from sqlmodel import select

from app.db.session import SessionLocal
from app.models.incident import Finding, Incident


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

        context = {
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
                "summary": incident.summary,
                "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
                "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
            },
            "findings": [
                {
                    "finding_id": f"FND-{f.id:06d}" if f.id else "",
                    "detector_id": f.detector_id,
                    "detector_version": f.detector_version,
                    "incident_type": f.incident_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "source_ip": f.source_ip,
                    "destination_ip": f.destination_ip,
                    "evidence": f.evidence_summary.split("; ") if f.evidence_summary else [],
                }
                for f in findings
            ],
            "asset": incident.asset_context or {
                "ip": incident.destination_ip,
                "name": f"host-{incident.destination_ip.replace('.', '-')}" if incident.destination_ip else "unknown",
                "criticality": incident.severity,
                "internet_facing": True
            }
        }

        print(json.dumps(context, indent=2, default=str))


if __name__ == "__main__":
    main()
