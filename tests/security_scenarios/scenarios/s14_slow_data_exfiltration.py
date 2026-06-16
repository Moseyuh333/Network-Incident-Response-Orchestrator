"""s14: Slow data exfiltration — many small transfers.

Attacker drips data in 5MB chunks over 30 minutes to stay under the 50MB
threshold per destination. Total volume is 150MB which is 3x the
threshold, but no single window hits it.
"""

from __future__ import annotations

from datetime import timedelta

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class SlowDataExfiltration(Scenario):
    id = "s14"
    title = "Slow exfiltration (5MB chunks, 30 minutes)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: exfil_window_seconds=300. 5MB every 5 minutes never reaches the "
        "50MB threshold inside any single window. Real-world APT groups do "
        "exactly this. Mitigation: keep rolling counters per destination or "
        "switch to a rate-based detector (MB/hour)."
    )

    def build_events(self, alloc: IpAllocator):
        insider = alloc.unique_ip("attacker")
        c2 = alloc.unique_ip("c2")
        ts = now()
        out = []
        for i in range(30):
            out.append(
                event(
                    external_id=f"{self.id}-{i:02d}",
                    source_ip=insider,
                    destination_ip=c2,
                    destination_port=443,
                    event_type="web",
                    action="allowed",
                    protocol="HTTPS",
                    bytes_out=5 * 1_048_576,
                    bytes_in=10_000,
                    user_agent="curl/8.0",
                    timestamp=ts + timedelta(minutes=i),
                    severity="low",
                )
            )
        return out
