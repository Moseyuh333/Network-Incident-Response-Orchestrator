"""Load synthetic events for N.I.R.O. demo scenarios."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from sqlmodel import Session

from app.db.session import engine, create_db_and_tables
from app.models.incident import Incident
from app.schemas.event import EventCreate
from app.services.ingestion import ingest_event, process_events
from sqlmodel import select


def load_ssh_bruteforce(session: Session) -> list[EventCreate]:
    # 6 failed login attempts to simulate brute force
    now = datetime.now(timezone.utc)
    events = []
    for i in range(6):
        events.append(
            EventCreate(
                external_event_id=f"demo-ssh-bf-{i}",
                timestamp=now - timedelta(seconds=(5 - i) * 10),
                sensor="sensor-internal-01",
                source_type="syslog",
                source_ip="192.168.1.150",
                destination_ip="192.168.2.5",
                source_port=51000 + i,
                destination_port=22,
                protocol="TCP",
                event_type="ssh",
                action="failed_login",
                username="admin",
                severity="medium",
            )
        )
    return events


def load_port_scan(session: Session) -> list[EventCreate]:
    # 12 distinct ports to simulate port scan (threshold is 10)
    now = datetime.now(timezone.utc)
    events = []
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 445, 1433, 3306, 3389]):
        events.append(
            EventCreate(
                external_event_id=f"demo-scan-{port}",
                timestamp=now - timedelta(seconds=(12 - i) * 5),
                sensor="sensor-internal-01",
                source_type="firewall",
                source_ip="192.168.1.180",
                destination_ip="192.168.2.6",
                source_port=49000 + i,
                destination_port=port,
                protocol="TCP",
                event_type="firewall",
                action="denied",
                severity="low",
            )
        )
    return events


def load_c2_beaconing(session: Session) -> list[EventCreate]:
    # 7 periodic connections spaced exactly 15 seconds apart to public IP
    now = datetime.now(timezone.utc)
    events = []
    for i in range(7):
        events.append(
            EventCreate(
                external_event_id=f"demo-c2-{i}",
                timestamp=now - timedelta(seconds=(7 - i) * 15),
                sensor="sensor-perimeter-01",
                source_type="suricata",
                source_ip="192.168.2.22",
                destination_ip="8.8.8.8",
                source_port=52000,
                destination_port=443,
                protocol="TCP",
                event_type="web",
                action="allowed",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) C2Beacon/1.0",
                severity="medium",
            )
        )
    return events


def load_data_exfil(session: Session) -> list[EventCreate]:
    # large outbound data to public IP (> 50MB)
    now = datetime.now(timezone.utc)
    return [
        EventCreate(
            external_event_id="demo-exfil-01",
            timestamp=now - timedelta(minutes=1),
            sensor="sensor-perimeter-01",
            source_type="suricata",
            source_ip="192.168.2.22",
            destination_ip="8.8.8.9",
            source_port=53000,
            destination_port=443,
            protocol="TCP",
            event_type="web",
            action="allowed",
            bytes_out=60 * 1024 * 1024,  # 60 MB
            severity="medium",
        )
    ]


def load_false_positive(session: Session) -> list[EventCreate]:
    # scan events from approved scanner IP (10.0.0.99)
    now = datetime.now(timezone.utc)
    events = []
    # Approved scanner in policies
    for i, port in enumerate([21, 22, 23, 25, 80, 443]):
        events.append(
            EventCreate(
                external_event_id=f"demo-fp-{port}",
                timestamp=now - timedelta(seconds=(6 - i) * 5),
                sensor="sensor-internal-01",
                source_type="firewall",
                source_ip="10.0.0.99",
                destination_ip="10.0.0.6",
                source_port=48000 + i,
                destination_port=port,
                protocol="TCP",
                event_type="firewall",
                action="denied",
                severity="low",
            )
        )
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Load demo scenarios for N.I.R.O.")
    parser.add_argument(
        "--scenario",
        required=True,
        choices=["ssh-bruteforce", "port-scan", "c2-beaconing", "data-exfil", "false-positive"],
        help="Demo scenario to load",
    )
    args = parser.parse_args()

    create_db_and_tables()

    with Session(engine) as session:
        if args.scenario == "ssh-bruteforce":
            payloads = load_ssh_bruteforce(session)
        elif args.scenario == "port-scan":
            payloads = load_port_scan(session)
        elif args.scenario == "c2-beaconing":
            payloads = load_c2_beaconing(session)
        elif args.scenario == "data-exfil":
            payloads = load_data_exfil(session)
        elif args.scenario == "false-positive":
            payloads = load_false_positive(session)
        else:
            payloads = []

        # Clean up existing demo events to ensure new IPs and timestamps are used
        from app.models.event import Event
        for item in payloads:
            if item.external_event_id:
                existing = session.exec(
                    select(Event).where(Event.external_event_id == item.external_event_id)
                ).first()
                if existing:
                    session.delete(existing)
        session.commit()

        events = [ingest_event(session, item) for item in payloads]
        incidents = process_events(session, events)

        if incidents:
            # `process_events` returns the same incident once per correlated finding.
            # Deduplicate by incident id so the success message is printed once per scenario,
            # and surface the total finding count so operators know correlation happened.
            unique_by_id: dict[int, Incident] = {inc.id: inc for inc in incidents if inc.id is not None}
            primary = next(iter(unique_by_id.values()))
            extra = len(unique_by_id) - 1
            if extra:
                print(
                    f"[+] Loaded scenario '{args.scenario}'. Created Incident: "
                    f"{primary.public_id} (ID: {primary.id}) from {len(incidents)} correlated findings."
                )
            else:
                print(
                    f"[+] Loaded scenario '{args.scenario}'. Created Incident: "
                    f"{primary.public_id} (ID: {primary.id})"
                )
        else:
            # For false positive, events might be filtered, check if we need to force create or notify
            print(f"[+] Loaded scenario '{args.scenario}'. Ingested {len(events)} events. 0 incidents triggered (events likely filtered by policy).")


if __name__ == "__main__":
    main()
