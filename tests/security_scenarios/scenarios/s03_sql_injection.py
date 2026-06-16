"""s03: SQL injection — baseline detection."""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class SQLInjectionAttack(Scenario):
    id = "s03"
    title = "SQL injection in web URL"
    category = ScenarioCategory.DETECT
    expected_findings = ["Web Attack"]
    notes = "URL contains UNION SELECT and OR 1=1 tautology patterns."

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-01",
                source_ip=attacker,
                destination_ip=target,
                destination_port=80,
                event_type="web",
                action="allowed",
                protocol="HTTP",
                url="/products.php?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
                user_agent="sqlmap/1.7",
                timestamp=ts,
                severity="medium",
            ),
            event(
                external_id=f"{self.id}-02",
                source_ip=attacker,
                destination_ip=target,
                destination_port=80,
                event_type="web",
                action="allowed",
                protocol="HTTP",
                url="/login.php?user=admin%27%20OR%20%271%27%3D%271",
                user_agent="sqlmap/1.7",
                timestamp=ts,
                severity="medium",
            ),
        ]
