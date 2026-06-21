#!/usr/bin/env python3
"""Threat intelligence lookup script."""

from __future__ import annotations

import argparse
import json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--target-domain")
    args = parser.parse_args()

    # Simple mock reputation logic
    ip = args.target_ip
    is_malicious = False
    details = []

    # Mock bad IPs
    bad_ips = {"198.51.100.10", "203.0.113.77", "185.220.101.5"}  # mock bad IPs
    if ip in bad_ips:
        is_malicious = True
        details.append("IP listed on mock threat intel feed")
        if ip == "185.220.101.5":
            details.append("IP identified as known Tor Exit Node")

    score = 0.95 if is_malicious else 0.05
    category = "malicious" if is_malicious else "benign"

    print(json.dumps({
        "target_ip": ip,
        "target_domain": args.target_domain,
        "reputation_score": score,
        "category": category,
        "details": details,
        "status": "success"
    }, indent=2))


if __name__ == "__main__":
    main()
