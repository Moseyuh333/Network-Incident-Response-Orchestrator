"""Response action policy engine."""

from __future__ import annotations

import ipaddress
from typing import Any

from app.models.incident import ResponseAction

PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

LOW_RISK = {"simulate_notify_admin", "simulate_collect_evidence"}
HIGH_RISK = {"simulate_block_ip", "simulate_quarantine_host", "simulate_disable_user"}


def evaluate_action(action_type: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    """Return policy decision for a proposed action."""
    if action_type in LOW_RISK:
        return {"decision": "allowed", "requires_approval": False, "risk": "low"}
    if action_type in HIGH_RISK:
        if action_type == "simulate_block_ip":
            _validate_block_target(arguments or {})
        return {"decision": "requires_approval", "requires_approval": True, "risk": "high"}
    return {"decision": "denied", "requires_approval": True, "risk": "unknown"}


def execute_simulation(action: ResponseAction) -> dict[str, Any]:
    """Execute a lab-safe simulated action."""
    return {
        "simulated": True,
        "action_type": action.action_type,
        "arguments": action.arguments or {},
        "message": f"{action.action_type} completed in simulation mode",
    }


def rollback_simulation(action: ResponseAction) -> dict[str, Any]:
    """Rollback a lab-safe simulated action."""
    return {
        "simulated": True,
        "action_type": action.action_type,
        "message": f"{action.action_type} rollback completed in simulation mode",
    }


def _validate_block_target(arguments: dict[str, Any]) -> None:
    target = arguments.get("ip") or arguments.get("target")
    if not target:
        raise ValueError("simulate_block_ip requires ip")
    ip = ipaddress.ip_address(str(target))
    if any(ip in network for network in PROTECTED_NETWORKS):
        raise ValueError(f"protected IP cannot be blocked: {ip}")
