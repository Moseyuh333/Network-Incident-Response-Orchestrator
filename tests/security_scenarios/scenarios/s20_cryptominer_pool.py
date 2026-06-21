"""s20: Cryptominer pool connections — long, periodic mining traffic.

A miner connects to a stratum pool every 30s. This is exactly the C2
beaconing shape (periodic, same dst:port). Should fire as C2 Beaconing.
The ML detector should also flag it as anomalous volume of long-lived
outbound.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class CryptominerPool(Scenario):
    id = "s20"
    title = "Cryptominer pool connection (stratum+tcp)"
    category = ScenarioCategory.DETECT
    expected_findings = ["C2 Beaconing"]
    notes = (
        "Periodic 30s beacons to a stratum mining pool. Detected as C2 "
        "beaconing because the shape is identical. This is a true positive "
        "even though the C2 label is semantically wrong (it is a miner, not "
        "a C2). The rule doesn't distinguish; from the rule's perspective "
        "it's a periodic external connection."
    )

    def build_events(self, alloc: IpAllocator):
        infected = alloc.unique_ip("attacker")
        pool = alloc.unique_ip("c2")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=infected,
                destination_ip=pool,
                destination_port=3333,  # typical stratum+tcp port
                event_type="web",
                action="allowed",
                protocol="TCP",
                user_agent="xmrig/6.21",
                bytes_out=2048,
                bytes_in=512,
                timestamp=offset,
                severity="low",
            )
            for i, offset in enumerate(time_ladder(ts, [i * 30 for i in range(8)]))
        ]
