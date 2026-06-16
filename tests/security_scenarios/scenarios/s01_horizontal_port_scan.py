"""s01: Horizontal port scan — baseline detection."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class HorizontalPortScan(Scenario):
    id = "s01"
    title = "Horizontal port scan (baseline)"
    category = ScenarioCategory.DETECT
    expected_findings = ["Port Scan"]
    notes = "12 distinct destination ports from one source in a 60s window."

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        ts = now()
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 445, 1433, 3306, 3389]
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=attacker,
                destination_ip=target,
                destination_port=port,
                source_port=49000 + i,
                event_type="firewall",
                action="denied",
                timestamp=offset,
                severity="low",
            )
            for i, (port, offset) in enumerate(zip(ports, time_ladder(ts, list(range(0, 60, 5)))))
        ]
