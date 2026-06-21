"""s12: Jittered C2 — modern malware randomises beacon intervals.

The C2 rule tolerates jitter < 10s or jitter/avg < 0.2. Sophisticated C2s
use 30-50% jitter, which currently slips past the heuristic.
"""

from __future__ import annotations

import random
from datetime import timedelta

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class JitteredC2(Scenario):
    id = "s12"
    title = "C2 with 40% jitter (modern malware)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: rule_engine jitter check is `jitter < 10.0 or jitter/avg < 0.2`. "
        "Real-world C2s (Cobalt Strike sleep-mask, Mythic) routinely use 30-50% "
        "jitter. This scenario uses ~40% jitter and so should NOT fire. "
        "Mitigation: switch to autocorrelation / FFT-based periodicity scoring."
    )

    def build_events(self, alloc: IpAllocator):
        infected = alloc.unique_ip("attacker")
        c2 = alloc.unique_ip("c2")
        ts = now()
        # 12 beacons with 40% jitter around a 30s base interval
        rng = random.Random(42)
        out = []
        for i in range(12):
            offset = sum(int(rng.uniform(18, 42)) for _ in range(i + 1))
            out.append(
                event(
                    external_id=f"{self.id}-{i:02d}",
                    source_ip=infected,
                    destination_ip=c2,
                    destination_port=443,
                    event_type="web",
                    action="allowed",
                    protocol="TCP",
                    user_agent="Mozilla/5.0 (X11; Linux) Chrome/120",
                    bytes_out=512,
                    bytes_in=2048,
                    timestamp=ts + timedelta(seconds=offset),
                    severity="medium",
                )
            )
        return out
