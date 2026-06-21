"""s19: Phishing URL — credential-harvesting page on a lookalike domain.

The URL pattern ``/login.php`` and credential-style parameters are not
in the web-attack regex (it focuses on XSS / SQLi / traversal). So a
phishing page load looks like a normal web request. KNOWN_GAP.
"""

from __future__ import annotations

from tests.security_scenarios.base import Scenario, ScenarioCategory, register
from tests.security_scenarios.helpers import IpAllocator, event, now


@register
class PhishingURL(Scenario):
    id = "s19"
    title = "Phishing page (lookalike domain, credential form)"
    category = ScenarioCategory.KNOWN_GAP
    expected_findings = []
    notes = (
        "GAP: web-attack regex doesn't have a phishing pattern. The URL "
        "is structurally innocent. Mitigation options: (1) domain reputation "
        "feed, (2) Levenshtein-distance check on lookalike domains, (3) "
        "URL allowlist for known-good login pages."
    )

    def build_events(self, alloc: IpAllocator):
        victim = alloc.unique_ip("victim")
        phish_site = alloc.unique_ip("c2")
        ts = now()
        return [
            event(
                external_id=f"{self.id}-01",
                source_ip=victim,
                destination_ip=phish_site,
                destination_port=443,
                event_type="web",
                action="allowed",
                protocol="HTTPS",
                domain="login-microsoft-online.com",
                url="/login.php?sessionid=abc123",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120",
                timestamp=ts,
                severity="low",
            ),
            event(
                external_id=f"{self.id}-02",
                source_ip=victim,
                destination_ip=phish_site,
                destination_port=443,
                event_type="web",
                action="allowed",
                protocol="HTTPS",
                domain="login-microsoft-online.com",
                url="/verify-account.php?email=user@corp.com",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120",
                timestamp=ts,
                severity="low",
            ),
        ]
