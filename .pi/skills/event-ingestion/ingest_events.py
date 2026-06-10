#!/usr/bin/env python3
"""Event ingestion skill implementation."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.event import Event
from app.schemas.event import EventCreate
from app.services.ingestion import ingest_event as svc_ingest_event


def parse_suricata_eve(line: str) -> dict[str, Any] | None:
    """Parse a single Suricata EVE JSON line."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None

    if record.get("event_type") not in {"alert", "flow", "dns", "http", "tls", "anomaly"}:
        return None

    src_ip = record.get("src_ip") or record.get("source_ip")
    dst_ip = record.get("dest_ip") or record.get("destination_ip")
    if not src_ip or not dst_ip:
        return None

    return {
        "external_event_id": f"suricata-{record.get('flow_id', '')}-{record.get('timestamp', '')}",
        "timestamp": record.get("timestamp"),
        "sensor": record.get("sensor", "suricata"),
        "source_type": "suricata",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": record.get("src_port"),
        "destination_port": record.get("dest_port"),
        "protocol": record.get("proto", "").upper(),
        "event_type": record.get("event_type", "unknown"),
        "action": record.get("action"),
        "severity": record.get("alert", {}).get("severity") if record.get("event_type") == "alert" else None,
        "flow_id": record.get("flow_id"),
        "normalized": record,
        "raw": record,
    }


def parse_zeek_json(line: str) -> dict[str, Any] | None:
    """Parse a single Zeek JSON line."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None

    src_ip = record.get("id.orig_h") or record.get("src_ip")
    dst_ip = record.get("id.resp_h") or record.get("dst_ip")
    if not src_ip or not dst_ip:
        return None

    return {
        "external_event_id": f"zeek-{record.get('uid', '')}",
        "timestamp": record.get("ts"),
        "sensor": "zeek",
        "source_type": "zeek",
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": record.get("id.orig_p"),
        "destination_port": record.get("id.resp_p"),
        "protocol": record.get("proto", "").upper(),
        "event_type": "zeek",
        "action": None,
        "severity": None,
        "flow_id": record.get("uid"),
        "normalized": record,
        "raw": record,
    }


def parse_syslog(line: str) -> dict[str, Any] | None:
    """Minimal syslog parser - extend for production use."""
    # This is a placeholder - real implementation would use a proper syslog parser
    return None


def normalize_timestamp(ts: Any) -> datetime:
    """Normalize various timestamp formats to UTC datetime."""
    if ts is None:
        return datetime.utcnow()
    if isinstance(ts, (int, float)):
        return datetime.utcfromtimestamp(ts)
    if isinstance(ts, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
    return datetime.utcnow()


def ingest_file(path: Path, source: str) -> list[dict[str, Any]]:
    """Ingest events from a file."""
    results = []
    with SessionLocal() as session:
        with path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                parsed = None
                if source == "suricata":
                    parsed = parse_suricata_eve(line)
                elif source == "zeek":
                    parsed = parse_zeek_json(line)
                elif source == "syslog":
                    parsed = parse_syslog(line)

                if not parsed:
                    continue

                if parsed.get("timestamp"):
                    parsed["timestamp"] = normalize_timestamp(parsed["timestamp"])

                try:
                    event_create = EventCreate(**parsed)
                    event = svc_ingest_event(session, event_create)
                    results.append({
                        "id": event.id,
                        "external_event_id": event.external_event_id,
                        "status": "ingested"
                    })
                except Exception as e:
                    results.append({
                        "line": line_num,
                        "error": str(e),
                        "status": "failed"
                    })
    return results


def ingest_stdin(source: str) -> list[dict[str, Any]]:
    """Ingest events from stdin."""
    results = []
    with SessionLocal() as session:
        for line_num, line in enumerate(sys.stdin, 1):
            line = line.strip()
            if not line:
                continue

            parsed = None
            if source == "suricata":
                parsed = parse_suricata_eve(line)
            elif source == "zeek":
                parsed = parse_zeek_json(line)

            if not parsed:
                continue

            if parsed.get("timestamp"):
                parsed["timestamp"] = normalize_timestamp(parsed["timestamp"])

            try:
                event_create = EventCreate(**parsed)
                event = svc_ingest_event(session, event_create)
                results.append({
                    "id": event.id,
                    "external_event_id": event.external_event_id,
                    "status": "ingested"
                })
            except Exception as e:
                results.append({
                    "line": line_num,
                    "error": str(e),
                    "status": "failed"
                })
    return results


def main():
    parser = argparse.ArgumentParser(description="Event ingestion skill")
    parser.add_argument("--source", required=True, choices=["suricata", "zeek", "rest", "syslog"])
    parser.add_argument("--file", type=Path, help="Input file path")
    parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    args = parser.parse_args()

    if args.file:
        results = ingest_file(args.file, args.source)
    elif args.stdin:
        results = ingest_stdin(args.source)
    else:
        parser.error("Either --file or --stdin required")

    print(json.dumps({
        "source": args.source,
        "total": len(results),
        "ingested": sum(1 for r in results if r.get("status") == "ingested"),
        "failed": sum(1 for r in results if r.get("status") == "failed"),
        "results": results
    }, indent=2, default=str))


if __name__ == "__main__":
    main()