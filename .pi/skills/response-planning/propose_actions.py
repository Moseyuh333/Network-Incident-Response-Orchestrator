#!/usr/bin/env python3
"""Mitigation action recommender script."""

from __future__ import annotations

import argparse
import json

from app.db.session import SessionLocal
from app.models.incident import Incident
from app.services.actions import propose_action


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-id", required=True, type=int)
    args = parser.parse_args()

    with SessionLocal() as session:
        incident = session.get(Incident, args.incident_id)
        if not incident:
            print(json.dumps({"error": f"Incident {args.incident_id} not found"}))
            return

        actions = []
        inc_type = incident.incident_type.lower()

        # Build list of suggested containment action types
        if any(tok in inc_type for tok in ("scan", "web", "brute", "exfil", "c2")):
            if incident.source_ip:
                actions.append({
                    "action_type": "simulate_block_ip",
                    "arguments": {"ip": incident.source_ip}
                })
        if any(tok in inc_type for tok in ("web", "exfil", "c2")):
            if incident.destination_ip:
                actions.append({
                    "action_type": "simulate_quarantine_host",
                    "arguments": {"ip": incident.destination_ip}
                })
        if "brute" in inc_type:
            actions.append({
                "action_type": "simulate_disable_user",
                "arguments": {"username": "attacker_or_compromised_user"}
            })

        # Always add a notification
        actions.append({
            "action_type": "simulate_notify_admin",
            "arguments": {"message": f"Incident {incident.public_id} of type {incident.incident_type} requires review."}
        })

        proposals = []
        for act in actions:
            try:
                action_record = propose_action(
                    session,
                    incident.id,
                    act["action_type"],
                    act["arguments"],
                    proposed_by="agent"
                )
                proposals.append({
                    "id": action_record.id,
                    "action_type": action_record.action_type,
                    "arguments": action_record.arguments,
                    "risk": action_record.risk,
                    "status": action_record.status,
                    "requires_approval": action_record.requires_approval
                })
            except Exception:
                # Log or handle denied by policy
                continue

        print(json.dumps({
            "incident_id": incident.id,
            "proposals": proposals,
            "status": "completed"
        }, indent=2))


if __name__ == "__main__":
    main()
