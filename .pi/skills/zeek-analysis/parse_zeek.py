#!/usr/bin/env python3
"""Zeek JSON log analysis skill implementation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.collectors.zeek import parse_zeek_file


def main():
    parser = argparse.ArgumentParser(description="Zeek JSON log analysis skill")
    parser.add_argument("--file", type=Path, required=True, help="Path to Zeek JSON log file")
    parser.add_argument("--type", choices=["conn", "dns", "http", "ssl", "notice"], help="Filter by log type")
    parser.add_argument("--incident-id", type=int, help="Optional incident ID to filter events")
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({"error": f"File not found: {args.file}", "results": {}}), file=sys.stderr)
        sys.exit(1)

    results = parse_zeek_file(args.file)

    if args.type:
        results = {args.type: results.get(args.type, [])}

    output = {
        "source": "zeek",
        "file": str(args.file),
        "log_type_filter": args.type,
        "counts": {k: len(v) for k, v in results.items()},
        "results": results
    }

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()