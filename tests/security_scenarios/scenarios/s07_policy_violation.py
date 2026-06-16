"""s07: Policy violation — baseline detection (blocked port)."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class PolicyViolation(Scenario):
    id = "s07"
    title = "Access to blocked management port (445)"
    category = ScenarioCategory.DETECT
    expected_findings = ["Policy Violation"]
    notes = "Direct connection attempt to SMB port 445 from external host."

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-01",
                source_ip=attacker,
                destination_ip=target,
                destination_port=445,
                event_type="firewall",
                action="denied",
                protocol="TCP",
                timestamp=ts,
                severity="medium",
            )
        ]
