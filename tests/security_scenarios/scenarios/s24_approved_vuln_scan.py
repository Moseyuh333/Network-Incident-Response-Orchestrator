"""s24: Approved vulnerability scan from a known scanner IP.

The rule engine filters events from the ``approved_scanners`` allowlist
(see policy: 10.0.0.99). We send a scan from that IP and verify that the
allowlist suppresses the port-scan finding.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class ApprovedVulnScan(Scenario):
    id = "s24"
    title = "False positive: vuln scan from approved scanner IP"
    category = ScenarioCategory.FALSE_POSITIVE
    expected_findings = []
    notes = (
        "EXPECTED: NO detection. The ``approved_scanners: ['10.0.0.99']`` "
        "allowlist in the policy file should suppress port-scan findings "
        "from this IP. This is the only source-IP-based filter active in "
        "the rule engine."
    )

    def build_events(self, alloc: IpAllocator):
        target = alloc.unique_ip("victim")
        ts = now()
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 445, 1433, 3306, 3389]
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip="10.0.0.99",  # approved scanner
                destination_ip=target,
                destination_port=port,
                source_port=49000 + i,
                event_type="firewall",
                action="allowed",
                timestamp=offset,
                severity="low",
            )
            for i, (port, offset) in enumerate(
                zip(ports, time_ladder(ts, list(range(0, 60, 5))))
            )
        ]
