"""s06: HTTP flood / DDoS — baseline detection."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class DDoSFlood(Scenario):
    id = "s06"
    title = "HTTP flood targeting a single host"
    category = ScenarioCategory.DETECT
    expected_findings = ["DDoS/Flood"]
    notes = "150 events to one target in 60s, well above the 100 threshold."

    def build_events(self, alloc: IpAllocator):
        target = alloc.unique_ip("victim")
        ts = now()
        # Spread 150 events from a botnet over 60 seconds
        return [
            event(
                external_id=f"{self.id}-{i:03d}",
                source_ip=f"198.51.100.{(i % 50) + 1}",  # botnet pool
                destination_ip=target,
                destination_port=80,
                source_port=40000 + i,
                event_type="web",
                action="allowed",
                protocol="HTTP",
                url="/",
                user_agent="bot/1.0",
                timestamp=offset,
                severity="low",
            )
            for i, offset in enumerate(time_ladder(ts, [i * 0.4 for i in range(150)]))
        ]
