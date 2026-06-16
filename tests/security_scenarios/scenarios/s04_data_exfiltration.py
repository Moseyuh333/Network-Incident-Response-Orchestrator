"""s04: Data exfiltration — baseline detection."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class DataExfiltration(Scenario):
    id = "s04"
    title = "Bulk data exfiltration to public host"
    category = ScenarioCategory.DETECT
    expected_findings = ["Data Exfiltration"]
    notes = "Single 60MB outbound transfer to public IP, exceeds 50MB threshold."

    def build_events(self, alloc: IpAllocator):
        insider = alloc.unique_ip("attacker")
        c2 = alloc.unique_ip("c2")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-01",
                source_ip=insider,
                destination_ip=c2,
                destination_port=443,
                source_port=52000,
                event_type="web",
                action="allowed",
                protocol="HTTPS",
                bytes_out=60 * 1_048_576,
                bytes_in=5_000,
                user_agent="curl/8.0",
                timestamp=ts,
                severity="high",
            )
        ]
