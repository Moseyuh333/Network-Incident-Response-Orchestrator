"""Zeek JSON log parser."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.schemas.event import EventCreate


def parse_zeek_file(path: Path, log_type: str = "conn") -> list[EventCreate]:
    events: list[EventCreate] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(parse_zeek_record(json.loads(line), log_type))
    return events


def parse_zeek_record(record: dict[str, Any], log_type: str = "conn") -> EventCreate:
    return EventCreate(
        external_event_id=str(record.get("uid") or ""),
        timestamp=_parse_ts(record.get("ts")),
        sensor="zeek",
        source_type="zeek",
        source_ip=record.get("id.orig_h", ""),
        destination_ip=record.get("id.resp_h", ""),
        source_port=record.get("id.orig_p"),
        destination_port=record.get("id.resp_p"),
        protocol=record.get("proto"),
        event_type=log_type,
        action=record.get("conn_state") or record.get("note"),
        url=record.get("uri"),
        domain=record.get("query") or record.get("server_name"),
        flow_id=record.get("uid"),
        bytes_in=int(record.get("orig_bytes") or 0),
        bytes_out=int(record.get("resp_bytes") or 0),
        raw=record,
    )


def _parse_ts(value: float | int | str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value))
