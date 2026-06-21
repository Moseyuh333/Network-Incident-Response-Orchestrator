"""s23: Backup traffic — legitimate large transfer to backup server.

A scheduled nightly backup streams 80MB to an internal backup server. The
exfil rule will fire because it can't tell a backup from an exfiltration.
This is a false positive that demonstrates the rule is over-eager.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class BackupTrafficFP(Scenario):
    id = "s23"
    title = "False positive: nightly backup to internal server"
    category = ScenarioCategory.FALSE_POSITIVE
    expected_findings = []
    notes = (
        "EXPECTED: NO detection (this is legitimate traffic). NOTE: the "
        "current exfil rule DOES fire on this because it can't distinguish "
        "backups from exfiltration. Mitigation: trusted-destination "
        "allowlist (e.g. backup.company.local)."
    )

    def build_events(self, alloc: IpAllocator):
        # Backup is internal-to-internal so exfil rule (which only checks
        # public destinations) should NOT fire. Verifies the rule's scope.
        source = alloc.unique_ip("attacker")
        backup = alloc.unique_ip("victim")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-01",
                source_ip=source,
                destination_ip=backup,
                destination_port=443,
                event_type="web",
                action="allowed",
                protocol="HTTPS",
                bytes_out=80 * 1_048_576,
                user_agent="BackupClient/2.1",
                timestamp=ts,
                severity="low",
            )
        ]
