"""s22: Multi-stage attack — scan, exploit, exfil, beacon.

A realistic 4-stage intrusion. The rule engine detects individual stages
but does NOT correlate them into a single 'intrusion' incident. So we
expect Port Scan + Web Attack + Data Exfiltration + C2 Beaconing as
separate findings, demonstrating the system can see each phase even if
it doesn't join them.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now, time_ladder


@register
class MultiStageAttack(Scenario):
    id = "s22"
    title = "Multi-stage attack (scan → exploit → exfil → beacon)"
    category = ScenarioCategory.DETECT
    expected_findings = ["Port Scan", "Web Attack", "Data Exfiltration", "C2 Beaconing"]
    notes = (
        "Each stage fires its own rule. The 'gap' here is that no single "
        "incident is raised for the full intrusion — they are correlated "
        "only by sharing source/dest IPs, not by temporal sequence. The "
        "correlation logic in app.services.ingestion.correlate_finding does "
        "group findings by (type, source, dest) within 24h, so port-scan "
        "findings will be grouped into one incident, web-attack into "
        "another, etc. Multi-stage correlation is a known roadmap item."
    )

    def build_events(self, alloc: IpAllocator):
        attacker = alloc.unique_ip("attacker")
        target = alloc.unique_ip("victim")
        c2 = alloc.unique_ip("c2")
        ts = now()

        # Stage 1: port scan (12 ports)
        scan = [
            event(
                external_id=f"{self.id}-scan-{i:02d}",
                source_ip=attacker,
                destination_ip=target,
                destination_port=port,
                source_port=49000 + i,
                event_type="firewall",
                action="denied",
                timestamp=offset,
                severity="low",
            )
            for i, (port, offset) in enumerate(
                zip(
                    [21, 22, 23, 25, 53, 80, 110, 139, 445, 1433, 3306, 3389],
                    time_ladder(ts, [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55]),
                )
            )
        ]

        # Stage 2: exploit (SQL injection) at ts+60
        exploit = [
            event(
                external_id=f"{self.id}-exploit-01",
                source_ip=attacker,
                destination_ip=target,
                destination_port=80,
                event_type="web",
                action="allowed",
                protocol="HTTP",
                url="/api/users?id=1%27%20UNION%20SELECT%20*%20FROM%20admin--",
                user_agent="sqlmap/1.7",
                timestamp=time_ladder(ts, [60])[0],
                severity="high",
            )
        ]

        # Stage 3: exfiltration at ts+120
        exfil = [
            event(
                external_id=f"{self.id}-exfil-01",
                source_ip=target,  # now exfil comes FROM the victim
                destination_ip=c2,
                destination_port=443,
                event_type="web",
                action="allowed",
                protocol="HTTPS",
                bytes_out=80 * 1_048_576,
                user_agent="curl/8.0",
                timestamp=time_ladder(ts, [120])[0],
                severity="high",
            )
        ]

        # Stage 4: C2 beaconing at ts+200, ts+230, ts+260, ts+290, ts+320, ts+350, ts+380
        beacon_offsets = time_ladder(ts, [200 + i * 30 for i in range(7)])
        beacon = [
            event(
                external_id=f"{self.id}-beacon-{i:02d}",
                source_ip=target,
                destination_ip=c2,
                destination_port=443,
                event_type="web",
                action="allowed",
                protocol="TCP",
                user_agent="C2/1.0",
                bytes_out=256,
                bytes_in=512,
                timestamp=beacon_offsets[i],
                severity="medium",
            )
            for i in range(7)
        ]

        return scan + exploit + exfil + beacon
