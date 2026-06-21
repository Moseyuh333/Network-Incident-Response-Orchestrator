#!/usr/bin/env python3
"""Suricata EVE JSON analysis skill implementation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.collectors.suricata import parse_eve_file


def main():
    parser = argparse.ArgumentParser(description="Suricata EVE JSON analysis skill")
    parser.add_argument("--file", type=Path, required=True, help="Path to EVE JSON file")
    parser.add_argument("--incident-id", type=int, help="Optional incident ID to filter events")
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({"error": f"File not found: {args.file}", "results": {}}), file=sys.stderr)
        sys.exit(1)

    results = parse_eve_file(args.file)

    if args.incident_id:
        # Filter results by incident_id if needed
        # This would require incident-to-event mapping in production
        pass

    output = {
        "source": "suricata",
        "file": str(args.file),
        "counts": {k: len(v) for k, v in results.items()},
        "results": results
    }

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()