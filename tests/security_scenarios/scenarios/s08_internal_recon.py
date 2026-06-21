"""s08: Internal reconnaissance — insider host scanning the corporate subnet."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class InternalRecon(Scenario):
    id = "s08"
    title = "Internal host scans 12 corporate servers"
    category = ScenarioCategory.DETECT
    expected_findings = ["Port Scan", "Policy Violation"]
    notes = "Compromised insider pivots across the internal network."

    def build_events(self, alloc: IpAllocator):
        insider = alloc.unique_ip("attacker")
        ts = now()
        # 12 distinct target hosts in 10.0.0.x, each on a blocked port
        targets = [f"10.0.1.{i}" for i in range(1, 13)]
        ports = [22, 445, 3389, 3306, 5432, 6379, 9200, 5900, 1433, 135, 139, 3389]
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=insider,
                destination_ip=target,
                destination_port=port,
                source_port=50000 + i,
                event_type="firewall",
                action="denied",
                protocol="TCP",
                timestamp=offset,
                severity="medium",
            )
            for i, (target, port, offset) in enumerate(
                zip(targets, ports, time_ladder(ts, list(range(0, 60, 5))))
            )
        ]
