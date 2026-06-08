"""Offline data collectors used by the incident-response pipeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def collect_recon(alert: dict[str, Any]) -> dict[str, Any]:
    """Return host and network context for the alert."""
    source_ip = alert.get("source_ip", "10.10.5.23")
    destination_ip = alert.get("destination_ip", "203.0.113.77")
    return {
        "source_host": {
            "ip": source_ip,
            "hostname": "ws-finance-023",
            "owner": "Finance Department",
            "asset_criticality": "high",
            "open_ports": [22, 443, 445, 3389],
            "last_vulnerability_scan": "2026-06-07",
            "observed_processes": ["powershell.exe", "rclone.exe", "chrome.exe"],
        },
        "destination": {
            "ip": destination_ip,
            "reputation": "suspicious",
            "asn": "AS64500 Example Transit",
            "country": "ZZ",
            "first_seen": "2026-06-08T07:55:00Z",
        },
        "network_zone": "corp-user-vlan-10",
    }


def collect_logs(alert: dict[str, Any]) -> dict[str, Any]:
    """Return normalized log events around the alert window."""
    base = _parse_timestamp(alert.get("timestamp"))
    source_ip = alert.get("source_ip", "10.10.5.23")
    destination_ip = alert.get("destination_ip", "203.0.113.77")
    events: list[dict[str, Any]] = []

    for index in range(8):
        events.append(
            {
                "timestamp": (base + timedelta(seconds=index * 10)).isoformat(),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": 443,
                "protocol": "tcp",
                "event_type": "proxy",
                "action": "allowed",
                "url": f"https://sync.example.invalid/api/{index}",
                "bytes_out": 7_500_000 + index * 250_000,
                "user_agent": "Mozilla/5.0 background-sync",
            }
        )

    for index, port in enumerate([22, 80, 135, 139, 445, 3389, 5900, 6379, 9200, 1433]):
        events.append(
            {
                "timestamp": (base - timedelta(seconds=45 - index)).isoformat(),
                "source_ip": source_ip,
                "destination_ip": f"10.10.9.{20 + index}",
                "destination_port": port,
                "protocol": "tcp",
                "event_type": "flow",
                "action": "syn",
                "bytes_out": 80,
            }
        )

    return {
        "event_count": len(events),
        "sources": ["proxy", "firewall", "edr"],
        "events": events,
        "notable_log_lines": [
            "Repeated TLS connections to suspicious external host",
            "High outbound transfer volume from workstation",
            "Endpoint telemetry observed rclone.exe shortly before alert",
        ],
    }


def extract_pcap_features(alert: dict[str, Any]) -> dict[str, Any]:
    """Return lightweight PCAP-derived features for the alert."""
    destination_ip = alert.get("destination_ip", "203.0.113.77")
    return {
        "flow_count": 8,
        "unique_external_destinations": 1,
        "primary_external_destination": destination_ip,
        "total_bytes_out": 69_000_000,
        "total_bytes_in": 850_000,
        "avg_beacon_interval_seconds": 10.0,
        "jitter_seconds": 1.4,
        "tls_sni_values": ["sync.example.invalid"],
        "protocols": {"tcp": 8, "udp": 0},
        "pcap_window_seconds": 80,
    }
