"""MITRE ATT&CK mapping and containment playbooks."""

from __future__ import annotations

from typing import Any


MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1071.001": {
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol: Web Protocols",
        "technique_id": "T1071.001",
    },
    "T1041": {
        "tactic": "Exfiltration",
        "technique": "Exfiltration Over C2 Channel",
        "technique_id": "T1041",
    },
    "T1105": {
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer",
        "technique_id": "T1105",
    },
    "T1046": {
        "tactic": "Discovery",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
    },
    "T1110": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
    },
    "T1190": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },
}


def map_to_mitre(classification: dict[str, Any]) -> list[dict[str, str]]:
    """Map the classification to ATT&CK techniques."""
    profile = classification.get("profile_scores", [{}])[0]
    profile_id = profile.get("profile_id", "")
    if profile_id == "c2_beaconing":
        technique_ids = ["T1071.001", "T1041", "T1105"]
    elif profile_id == "port_scan":
        technique_ids = ["T1046"]
    elif profile_id == "brute_force":
        technique_ids = ["T1110"]
    elif profile_id == "web_attack":
        technique_ids = ["T1190"]
    else:
        technique_ids = ["T1046"]
    return [MITRE_TECHNIQUES[technique_id] for technique_id in technique_ids]


def build_containment_plan(
    alert: dict[str, Any],
    classification: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return defensive containment actions for the incident."""
    source_ip = alert.get("source_ip", "unknown")
    destination_ip = alert.get("destination_ip", "unknown")
    return [
        {
            "step": 1,
            "action": f"Isolate host {source_ip} from user VLAN",
            "owner": "SOC L2",
            "mode": "approval_required",
            "risk": "medium",
        },
        {
            "step": 2,
            "action": f"Block outbound traffic to {destination_ip}",
            "owner": "Network Security",
            "mode": "simulate_by_default",
            "risk": "low",
        },
        {
            "step": 3,
            "action": "Collect volatile endpoint evidence and full packet capture",
            "owner": "DFIR",
            "mode": "manual",
            "risk": "low",
        },
        {
            "step": 4,
            "action": "Rotate credentials for the affected user and review OAuth tokens",
            "owner": "IAM",
            "mode": "approval_required",
            "risk": "medium",
        },
        {
            "step": 5,
            "action": f"Open IR bridge for {classification['severity']} severity tracking",
            "owner": "Incident Commander",
            "mode": "manual",
            "risk": "low",
        },
    ]
