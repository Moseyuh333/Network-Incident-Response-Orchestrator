"""s16: HTTPS exfiltration chunked into medium-sized requests.

A 60MB exfil is one event → detector fires (s04). Real attackers chunk
it into 5MB HTTPS requests spaced 30s apart. Each individual request is
small enough to slip past the 50MB/300s window.
"""

from __future__ import annotations

from datetime import timedelta

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class ChunkedHTTPSExfil(Scenario):
    id = "s16"
    title = "Chunked HTTPS exfil (5MB × 12 requests, 30s apart)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: same root cause as s14 (slow exfil). 5MB chunks over 6 minutes "
        "never aggregate above 50MB in the rolling window. ML could potentially "
        "flag this if it saw a per-flow aggregate, but it currently only "
        "examines one event at a time."
    )

    def build_events(self, alloc: IpAllocator):
        insider = alloc.unique_ip("attacker")
        c2 = alloc.unique_ip("c2")
        ts = now()
        out = []
        for i in range(12):
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
                    bytes_in=5_000,
                    user_agent="curl/8.0",
                    timestamp=ts + timedelta(seconds=i * 30),
                    severity="low",
                )
            )
        return out
