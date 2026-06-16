"""Event builders + IP allocator for the scenario harness.

The allocators hand out RFC5737 documentation IPs (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) so scenarios never collide with the
real demo data and with each other across reruns.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from app.schemas.event import EventCreate


# Three documentation IP ranges (RFC5737) — guaranteed not to collide
# with real-world traffic and not on the trusted_ips list.
_ROLE_PREFIXES = {
    "attacker": "198.51.100",
    "victim": "203.0.113",
    "c2": "192.0.2",
    "tor": "192.0.2",
    "legit": "198.51.100",
}


class IpAllocator:
    """Hand out a fresh IP per role per scenario."""

    def __init__(self, scenario_id: str) -> None:
        # Use the scenario id as a salt so two scenarios don't both get
        # .1 in the same subnet and step on each other.
        salt = abs(hash(scenario_id)) % 200
        self._counters: dict[str, itertools.count] = {
            role: itertools.count(salt + 1) for role in _ROLE_PREFIXES
        }

    def unique_ip(self, role: str) -> str:
        prefix = _ROLE_PREFIXES.get(role, "198.51.100")
        n = next(self._counters[role])
        return f"{prefix}.{n}.1"

    def public_ip(self, label: str = "ext") -> str:
        """Stable public IP for external services (Tor exit, CDN, etc)."""
        n = next(self._counters["c2"])
        return f"192.0.2.{n}"


def now() -> datetime:
    """Return a fresh 'now' anchored in UTC."""
    return datetime.now(timezone.utc)


def event(
    *,
    external_id: str,
    source_ip: str,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    source_port: int | None = None,
    protocol: str = "TCP",
    event_type: str = "firewall",
    action: str = "allowed",
    severity: str = "low",
    timestamp: datetime | None = None,
    url: str | None = None,
    user_agent: str | None = None,
    username: str | None = None,
    domain: str | None = None,
    bytes_in: int = 0,
    bytes_out: int = 0,
    sensor: str = "sensor-test-harness",
) -> EventCreate:
    """Build an EventCreate with sensible defaults so scenarios stay short."""
    return EventCreate(
        external_event_id=external_id,
        timestamp=timestamp or now(),
        sensor=sensor,
        source_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        event_type=event_type,
        action=action,
        username=username,
        url=url,
        domain=domain,
        user_agent=user_agent,
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        severity=severity,
    )


def time_ladder(base: datetime, seconds: list[int]) -> list[datetime]:
    """Return timestamps offset by `seconds` from `base`."""
    return [base + timedelta(seconds=s) for s in seconds]
