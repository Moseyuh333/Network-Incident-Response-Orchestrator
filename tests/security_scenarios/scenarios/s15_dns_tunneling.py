"""s15: DNS tunneling — exfiltrate data via high-entropy DNS queries.

Rule engine has no DNS-content detector. The rule only looks at port
counts, bytes, periodicity. A DNS tunnel looks like a bunch of low-byte
UDP/53 queries with no signal that triggers anything.
"""

from __future__ import annotations

import string
from datetime import timedelta

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


def _high_entropy_subdomain(seed: int, length: int = 40) -> str:
    """Generate a base32-ish string that looks like a DNS tunnel subdomain."""
    alphabet = string.ascii_lowercase + string.digits
    out = []
    s = seed
    for _ in range(length):
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(alphabet[s % len(alphabet)])
    return "".join(out)


@register
class DNSTunneling(Scenario):
    id = "s15"
    title = "DNS tunneling (high-entropy subdomain queries)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: no DNS-content detector. Mitigations: (1) per-domain entropy "
        "detector (Shannon > 4.5), (2) per-domain length detector (label > 30 "
        "chars), (3) NXDOMAIN rate spike, (4) TXT-record volume. The ML "
        "anomaly detector sees UDP/53 with low bytes_out and scores it as "
        "benign, so no flag here either."
    )

    def build_events(self, alloc: IpAllocator):
        infected = alloc.unique_ip("attacker")
        resolver = alloc.unique_ip("c2")
        ts = now()
        out = []
        for i in range(40):
            subdomain = _high_entropy_subdomain(seed=i + 1)
            out.append(
                event(
                    external_id=f"{self.id}-{i:02d}",
                    source_ip=infected,
                    destination_ip=resolver,
                    destination_port=53,
                    event_type="dns",
                    action="allowed",
                    protocol="UDP",
                    domain=f"{subdomain}.example-tunnel.com",
                    bytes_out=120,
                    bytes_in=400,
                    timestamp=ts + timedelta(seconds=i * 3),
                    severity="low",
                )
            )
        return out
