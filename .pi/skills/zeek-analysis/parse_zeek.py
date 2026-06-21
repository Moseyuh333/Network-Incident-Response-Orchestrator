#!/usr/bin/env python3
"""Zeek JSON log analysis skill implementation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from app.collectors.zeek import parse_zeek_file
from app.core.json import jsonable


def main():
    parser = argparse.ArgumentParser(description="Zeek JSON log analysis skill")
    parser.add_argument("--file", type=Path, required=True, help="Path to Zeek JSON log file")
    parser.add_argument("--type", choices=["conn", "dns", "http", "ssl", "notice"], help="Filter by log type")
    parser.add_argument("--incident-id", type=int, help="Optional incident ID to filter events")
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({"error": f"File not found: {args.file}", "results": {}}), file=sys.stderr)
        sys.exit(1)

    events = parse_zeek_file(args.file)

    # Group by ``event_type`` so the output mirrors the suricata-analysis skill
    # (the Zeek collector returns a flat list, not a dict).
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        event_type = getattr(event, "event_type", "unknown") or "unknown"
        grouped.setdefault(event_type, []).append(jsonable(event))

    if args.type:
        # Filter keeps only entries that match the requested Zeek log type.
        grouped = {args.type: grouped.get(args.type, [])}

    output = {
        "source": "zeek",
        "file": str(args.file),
        "log_type_filter": args.type,
        "counts": {k: len(v) for k, v in grouped.items()},
        "results": grouped,
    }

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()