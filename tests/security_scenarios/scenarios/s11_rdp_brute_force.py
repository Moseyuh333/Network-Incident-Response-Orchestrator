"""s11: RDP brute force on Windows.

The brute-force rule only checks ``event_type in ('ssh', 'auth', 'login',
'authentication')``. RDP events have ``event_type='rdp'`` so they are
invisible to the rule even though they are exactly the same shape of
attack.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class RDPBruteForce(Scenario):
    id = "s11"
    title = "RDP brute force (3389)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: rule_engine.detect_brute_force only matches event_type in "
        "{ssh, auth, login, authentication}. RDP/WinRM/RPC are missing. "
        "Mitigation: extend the event_type whitelist to include 'rdp', "
        "'winrm', 'rpc'."
    )

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=attacker,
                destination_ip=target,
                destination_port=3389,
                event_type="rdp",
                action="failed_login",
                username="Administrator",
                protocol="TCP",
                timestamp=offset,
                severity="high",
            )
            for i, offset in enumerate(time_ladder(ts, list(range(0, 120, 20))))
        ]
