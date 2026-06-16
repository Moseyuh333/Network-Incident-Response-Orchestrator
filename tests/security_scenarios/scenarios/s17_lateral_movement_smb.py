"""s17: Lateral movement via SMB to multiple internal hosts.

Compromised internal host moves through the network touching 445 on
several internal targets. Each individual connection is one event so the
port-scan rule sees the source port as 445 and destination ports as 445
(only 1 distinct port), and the policy-violation rule fires per event
on 445. We accept Policy Violation as a partial detection.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class LateralMovementSMB(Scenario):
    id = "s17"
    title = "Lateral movement via SMB (10 internal hosts)"
    category = ScenarioCategory.DETECT
    expected_findings = ["Policy Violation"]
    notes = (
        "Each connection to port 445 (blocked) fires a policy violation. The "
        "rule engine does NOT correlate 'same source hitting many internal "
        "hosts' as lateral movement — that's a known gap (no lateral-movement "
        "detector). We mark Policy Violation as the expected detection."
    )

    def build_events(self, alloc: IpAllocator):
        compromised = alloc.unique_ip("attacker")
        ts = now()
        targets = [f"10.0.2.{i}" for i in range(1, 11)]
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=compromised,
                destination_ip=target,
                destination_port=445,
                source_port=49000 + i,
                event_type="smb",
                action="allowed",
                protocol="TCP",
                bytes_out=4096,
                bytes_in=8192,
                timestamp=offset,
                severity="medium",
            )
            for i, (target, offset) in enumerate(
                zip(targets, time_ladder(ts, list(range(0, 60, 6))))
            )
        ]
