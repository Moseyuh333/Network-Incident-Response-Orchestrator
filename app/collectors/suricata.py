"""Suricata EVE JSON parser."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from app.schemas.event import EventCreate


def _event_id(record: dict[str, Any]) -> str:
    """Build a stable external_event_id for a Suricata record.

    Suricata EVE records do not always carry a unique id (``event_id``
    is optional, ``flow_id`` is per-flow not per-event). Falling back
    to a UUID ensures the events.external_event_id UNIQUE constraint
    is never violated by two events from the same PCAP / EVE file.
    """
    for key in ("event_id", "flow_id"):
        value = record.get(key)
        if value not in (None, ""):
            ts = record.get("timestamp", "")
            return f"suricata-{ts}-{value}"
    return f"suricata-{uuid.uuid4().hex[:16]}"


def parse_eve_file(path: Path) -> list[EventCreate]:
    events: list[EventCreate] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(parse_eve_record(json.loads(line)))
    return events


def parse_eve_record(record: dict[str, Any]) -> EventCreate:
    event_type = record.get("event_type", "unknown")
    alert = record.get("alert") or {}
    flow = record.get("flow") or {}
    http = record.get("http") or {}
    dns = record.get("dns") or {}
    return EventCreate(
        external_event_id=_event_id(record),
        timestamp=_parse_ts(record.get("timestamp")),
        sensor=record.get("sensor_name") or "suricata",
        source_type="suricata",
        source_ip=record.get("src_ip", ""),
        destination_ip=record.get("dest_ip", ""),
        source_port=record.get("src_port"),
        destination_port=record.get("dest_port"),
        protocol=record.get("proto"),
        event_type=event_type,
        action=alert.get("action") or record.get("action"),
        url=http.get("url"),
        domain=dns.get("rrname") or record.get("tls", {}).get("sni"),
        flow_id=str(record.get("flow_id")) if record.get("flow_id") is not None else None,
        severity=str(alert.get("severity")) if alert.get("severity") is not None else None,
        user_agent=http.get("http_user_agent"),
        bytes_in=int(flow.get("bytes_toserver") or 0),
        bytes_out=int(flow.get("bytes_toclient") or 0),
        raw=record,
    )


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
