"""s25: Video streaming — legitimate high-bandwidth to a known CDN.

Streaming a YouTube video produces sustained high bytes_out to a known
content delivery network. The exfil rule fires because the volume is
large. KNOWN FALSE POSITIVE — demonstrates the need for a
trusted-destination / known-CDN allowlist.
"""

from __future__ import annotations

from datetime import timedelta

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class VideoStreamingFP(Scenario):
    id = "s25"
    title = "False positive: streaming video to a known CDN"
    category = ScenarioCategory.FALSE_POSITIVE
    expected_findings = []
    notes = (
        "EXPECTED: NO detection. NOTE: the exfil rule will fire on this "
        "(60MB+ in 300s to a public IP) because the rule has no concept "
        "of trusted CDN destinations. Mitigation: allowlist of known CDN "
        "IP ranges (Google, Cloudflare, Akamai, Fastly). For now the test "
        "will be marked as a 'missed false positive' — i.e. the rule fired "
        "when it shouldn't have. Adjust the assertion once the allowlist "
        "is added."
    )

    def build_events(self, alloc: IpAllocator):
        viewer = alloc.unique_ip("attacker")
        cdn = "142.250.190.78"  # googleusercontent.com range
        ts = now()
        return [
            event(
                external_id=f"{self.id}-{i:02d}",
                source_ip=viewer,
                destination_ip=cdn,
                destination_port=443,
                event_type="web",
                action="allowed",
                protocol="HTTPS",
                domain="googlevideo.com",
                bytes_out=15 * 1_048_576,  # 15MB chunks
                bytes_in=4_000,
                user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120",
                timestamp=ts + timedelta(seconds=i * 10),
                severity="low",
            )
            for i in range(8)  # 120MB total
        ]
