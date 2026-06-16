"""s02: SSH brute force — baseline detection."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class SSHBruteForce(Scenario):
    id = "s02"
    title = "SSH brute force (baseline)"
    category = ScenarioCategory.DETECT
    expected_findings = ["Brute Force"]
    notes = "6 failed logins to the same account in 120s."

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=attacker,
                destination_ip=target,
                destination_port=22,
                source_port=51000 + i,
                event_type="ssh",
                action="failed_login",
                username="root",
                protocol="TCP",
                timestamp=offset,
                severity="medium",
            )
            for i, offset in enumerate(time_ladder(ts, list(range(0, 60, 10))))
        ]
