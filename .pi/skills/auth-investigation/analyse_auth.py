#!/usr/bin/env python3
"""Authentication events investigator script."""

from __future__ import annotations

import argparse
import json
from sqlmodel import select

from app.db.session import SessionLocal
from app.models.event import Event
from app.models.incident import Incident


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-id", required=True, type=int)
    args = parser.parse_args()

    with SessionLocal() as session:
        incident = session.get(Incident, args.incident_id)
        if not incident:
            print(json.dumps({"error": f"Incident {args.incident_id} not found"}))
            return

        stmt = select(Event).where(
            (Event.source_ip == incident.source_ip) | (Event.destination_ip == incident.destination_ip)
        )
        events = session.exec(stmt).all()

        auth_events = [
            e for e in events
            if e.event_type in ("ssh", "auth", "login", "authentication")
            or (e.action and any(tok in e.action.lower() for tok in ("login", "auth", "fail")))
        ]

        failures = [e for e in auth_events if e.action and "fail" in e.action.lower()]
        successes = [e for e in auth_events if e.action and "success" in e.action.lower()]
        usernames = sorted(list({e.username for e in auth_events if e.username}))

        print(json.dumps({
            "incident_id": args.incident_id,
            "total_auth_events": len(auth_events),
            "failed_attempts": len(failures),
            "successful_attempts": len(successes),
            "usernames_targeted": usernames,
            "findings": [
                f"{len(failures)} failed authentication attempts observed"
            ] if failures else []
        }, indent=2, default=str))


if __name__ == "__main__":
    main()
