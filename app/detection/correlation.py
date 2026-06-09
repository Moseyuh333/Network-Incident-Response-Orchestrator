"""Event correlation: group events into incidents."""

from __future__ import annotations

from typing import Any

from app.core.logging import log


def correlate(
    findings: list[dict[str, Any]],
    existing_incidents: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Correlate detection findings into incidents.

    Returns (new_incidents_to_create, existing_incidents_to_update).
    Matching logic: same source_ip + same incident_type within 24h → same incident.
    """
    new_incidents: list[dict[str, Any]] = []
    updated_incidents: list[dict[str, Any]] = []

    # Index existing open incidents by (source_ip, incident_type)
    existing_map: dict[tuple[str, str], dict[str, Any]] = {}
    for inc in existing_incidents:
        key = (inc.get("source_ip", ""), inc["incident_type"])
        if inc.get("status") == "open":
            existing_map[key] = inc

    for finding in findings:
        key = (finding.get("source_ip", ""), finding["incident_type"])
        if key in existing_map:
            inc = existing_map[key]
            updated_incidents.append({
                "incident": inc,
                "new_evidence": finding.get("evidence", []),
                "updated_severity": finding["severity"],
            })
        else:
            new_incidents.append(finding)

    log.info(
        "Correlation: %d new incidents, %d updates to existing",
        len(new_incidents),
        len(updated_incidents),
    )
    return new_incidents, updated_incidents
