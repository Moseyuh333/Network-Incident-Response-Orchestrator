"""s09: Slow port scan (low-and-slow) — likely missed by current rules.

Real-world attackers spread a scan over hours to slip past threshold-based
detectors. N.I.R.O.'s port-scan rule uses a 60s window, so this should
NOT be detected.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class SlowPortScan(Scenario):
    id = "s09"
    title = "Slow port scan (1 port per 5 minutes)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: port_scan_window_seconds=60. 12 ports over 60 minutes are far below "
        "the rolling window. Real attackers use this to evade. Mitigation would "
        "require a longer window or session-based aggregation."
    )

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        ts = now()
        ports = [22, 80, 443, 445, 3389, 8080, 3306, 5432, 6379, 9200, 27017, 25]
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
            for i, (port, offset) in enumerate(
                zip(ports, time_ladder(ts, [i * 300 for i in range(12)]))  # 5 min apart
            )
        ]
