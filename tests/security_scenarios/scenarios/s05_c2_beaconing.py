"""s05: C2 beaconing — baseline detection."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class C2Beaconing(Scenario):
    id = "s05"
    title = "C2 beaconing (low jitter, periodic)"
    category = ScenarioCategory.DETECT
    expected_findings = ["C2 Beaconing"]
    notes = "7 connections to the same host:port exactly 15s apart."

    def build_events(self, alloc: IpAllocator):
        infected = alloc.unique_ip("attacker")
        c2 = alloc.unique_ip("c2")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=infected,
                destination_ip=c2,
                destination_port=443,
                source_port=53000,
                event_type="web",
                action="allowed",
                protocol="TCP",
                user_agent="Mozilla/5.0 (Windows NT 10.0) CobaltStrike",
                timestamp=offset,
                bytes_out=256,
                bytes_in=512,
                severity="medium",
            )
            for i, offset in enumerate(time_ladder(ts, [i * 15 for i in range(7)]))
        ]
