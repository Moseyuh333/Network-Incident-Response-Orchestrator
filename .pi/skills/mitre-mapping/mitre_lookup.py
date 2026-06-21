#!/usr/bin/env python3
"""MITRE ATT&CK technique mapper script."""

from __future__ import annotations

import argparse
import json

MITRE_MAP = {
    "port_scan": {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "port scan": {"technique": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "brute_force": {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "brute force": {"technique": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "ssh_brute_force": {"technique": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "ssh brute force": {"technique": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "web_attack": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "web attack": {"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "data_exfiltration": {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "data exfiltration": {"technique": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "c2_beaconing": {"technique": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "c2 beaconing": {"technique": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "ddos_flood": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "ddos/flood": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "ddos": {"technique": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "policy_violation": {"technique": "T1040", "name": "Network Sniffing", "tactic": "Collection"},
    "policy violation": {"technique": "T1040", "name": "Network Sniffing", "tactic": "Collection"},
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-type", required=True)
    args = parser.parse_args()

    inc_type = args.incident_type.lower().strip()
    mapping = MITRE_MAP.get(inc_type)

    if not mapping:
        # fuzzy matching
        for k, v in MITRE_MAP.items():
            if k in inc_type or inc_type in k:
                mapping = v
                break

    if mapping:
        print(json.dumps({
            "tactic": mapping["tactic"],
            "technique_id": mapping["technique"],
            "technique_name": mapping["name"],
            "mapped": True
        }, indent=2))
    else:
        print(json.dumps({
            "tactic": "Unknown",
            "technique_id": "T0000",
            "technique_name": "Unclassified Technique",
            "mapped": False
        }, indent=2))


if __name__ == "__main__":
    main()
