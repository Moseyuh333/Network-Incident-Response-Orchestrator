"""s10: Distributed brute force — many IPs, 1 attempt each.

Evasion technique: stay under the per-source threshold by spreading across
many source IPs. N.I.R.O.'s brute-force rule is per-source-IP, so each
attacker stays at 1 attempt and is invisible.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class DistributedBruteForce(Scenario):
    id = "s10"
    title = "Distributed SSH brute force (10 IPs × 1 attempt)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: brute_force is per-source-IP with threshold=5. A botnet with "
        "1 attempt per IP stays invisible. Mitigation requires aggregating "
        "across sources targeting the same destination+user."
    )

    def build_events(self, alloc: IpAllocator):
        target = alloc.unique_ip("victim")
        ts = now()
        attackers = [f"198.51.100.{i + 50}" for i in range(10)]
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=src,
                destination_ip=target,
                destination_port=22,
                event_type="ssh",
                action="failed_login",
                username="admin",
                timestamp=offset,
                severity="medium",
            )
            for i, (src, offset) in enumerate(
                zip(attackers, time_ladder(ts, list(range(0, 60, 6))))
            )
        ]
