"""s18: Webshell activity — POST with command-injection-like parameters.

The web-attack regex ``[;&|`]\\s*(cat|ls|whoami|...)`` matches the
classic ``;cat /etc/passwd`` pattern. A webshell upload + exec should
fire Web Attack. We also test command-injection URL with `id` and `whoami`.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class WebshellActivity(Scenario):
    id = "s18"
    title = "Webshell command execution (POST with cmd parameter)"
    category = ScenarioCategory.DETECT
    expected_findings = ["Web Attack"]
    notes = (
        "URLs contain shell-metacharacter + command patterns which the web-attack "
        "regex detects. The rule does NOT know that the host has a webshell "
        "(would need a baseline of allowed URLs) but the URLs themselves look "
        "malicious so this should fire."
    )

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
                url="/uploads/shell.php?cmd=;id",
                user_agent="curl/8.0",
                timestamp=ts,
                severity="high",
            ),
            event(
                external_id=f"{self.id}-02",
                source_ip=attacker,
                destination_ip=target,
                destination_port=80,
                event_type="web",
                action="allowed",
                protocol="HTTP",
                url="/uploads/shell.php?cmd=|whoami",
                user_agent="curl/8.0",
                timestamp=ts,
                severity="high",
            ),
        ]
