#!/usr/bin/env python3
"""DNS events investigator script."""

from __future__ import annotations

import argparse
import json
from collections import Counter
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
        ).where(Event.event_type == "dns")
        events = session.exec(stmt).all()

        domains = [e.domain for e in events if e.domain]
        counts = Counter(domains)
        unique_domains = sorted(list(counts.keys()))

        suspicious_keywords = ("ngrok", "bypass", "malware", "exploit", "c2", "onion")
        suspicious = [
            d for d in unique_domains
            if any(kw in d.lower() for kw in suspicious_keywords)
        ]

        print(json.dumps({
            "incident_id": args.incident_id,
            "total_dns_queries": len(events),
            "unique_domains_queried": len(unique_domains),
            "top_domains": [{"domain": d, "count": c} for d, c in counts.most_common(5)],
            "suspicious_domains": suspicious,
        }, indent=2, default=str))


if __name__ == "__main__":
    main()
