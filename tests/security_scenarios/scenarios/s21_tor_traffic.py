"""s21: Tor traffic — connections to known Tor exit relays.

No Tor-exit-list detector. The connection is to a public IP on 443 or
9001, which is just a normal web/relay connection to the rule engine.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class TorTraffic(Scenario):
    id = "s21"
    title = "Tor traffic (connections to known exit relays)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: no Tor-exit-list or anonymity-network detector. Mitigation: "
        "subscribe to the dan.me.uk / TorProject exit list and check dst_ips. "
        "Could be added as a policy file (.pi/data/policies/tor_exits.json) "
        "and reused by the rule engine."
    )

    def build_events(self, alloc: IpAllocator):
        client = alloc.unique_ip("attacker")
        # Use Tor exit IP space
        tor_exits = [
            "185.220.101.1", "185.220.101.2", "185.220.101.3",
            "199.249.230.114", "199.249.230.115",
        ]
        ts = now()
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=client,
                destination_ip=tor_exits[i],
                destination_port=443,
                event_type="web",
                action="allowed",
                protocol="HTTPS",
                user_agent="Mozilla/5.0 (Windows NT 10.0; rv:120) Firefox/120",
                timestamp=offset,
                bytes_out=4096,
                bytes_in=16384,
                severity="low",
            )
            for i, offset in enumerate(time_ladder(ts, list(range(0, 30, 6))))
        ]
