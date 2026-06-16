"""s13: Credential stuffing — successful logins from many users.

Evasion: use valid credentials (no failures) so the brute-force rule
(``action contains 'fail'``) sees nothing. From the rule's perspective
this looks like normal authentication.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class CredentialStuffing(Scenario):
    id = "s13"
    title = "Credential stuffing (valid creds, many users)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: brute-force rule only triggers on failed logins. Credential "
        "stuffing with valid credentials is invisible. Mitigation: baseline "
        "per-user login rate and alert on impossible-travel / many-users-from-one-IP."
    )

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        ts = now()
        users = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "henry", "ivan", "judy"]
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=attacker,
                destination_ip=target,
                destination_port=443,
                event_type="auth",
                action="successful_login",
                username=user,
                protocol="HTTPS",
                timestamp=offset,
                severity="low",
            )
            for i, (user, offset) in enumerate(zip(users, time_ladder(ts, list(range(0, 30, 3)))))
        ]
