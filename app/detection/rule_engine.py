"""Rule-based detection engine for network security events."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from app.core.config import settings
from app.core.logging import log

# ── Incident type constants ─────────────────────────────────────────────
INCIDENT_PORT_SCAN = "Port Scan"
INCIDENT_BRUTE_FORCE = "Brute Force"
INCIDENT_WEB_ATTACK = "Web Attack"
INCIDENT_DATA_EXFIL = "Data Exfiltration"
INCIDENT_C2_BEACONING = "C2 Beaconing"
INCIDENT_DDOS = "DDoS/Flood"
INCIDENT_POLICY_VIOLATION = "Policy Violation"

# ── Web attack regex patterns (defensive samples only) ─────────────────
_WEB_ATTACK_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "SQL Injection (UNION/select)",
        re.compile(
            r"(\bunion\b\s+\bselect\b|\bselect\b.*\bfrom\b|'\+$|%27)",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL Injection (tautology)",
        re.compile(
            r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
            re.IGNORECASE,
        ),
    ),
    (
        "Path Traversal",
        re.compile(r"(\.\./|\.\.\\){2,}"),
    ),
    (
        "Command Injection",
        re.compile(
            r"([;&|`])\s*(cat|ls|whoami|id|pwd|curl|wget|nc|ncat|bash|sh\s)",
            re.IGNORECASE,
        ),
    ),
    (
        "XSS",
        re.compile(
            r"(<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=)",
            re.IGNORECASE,
        ),
    ),
    (
        "Sensitive file access",
        re.compile(
            r"(/etc/passwd|/etc/shadow|/proc/|\.env|web\.config|win\.ini|boot\.ini)",
            re.IGNORECASE,
        ),
    ),
]

# Ports commonly blocked in enterprise environments
_BLOCKED_PORTS = {135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200}

# Private/internal RFC1918 ranges (for flood detection — internal targets)
_PRIVATE_NETWORKS = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_NETWORKS)


def _window(
    events: list[dict[str, Any]], seconds: int
) -> list[dict[str, Any]]:
    """Return events within the last *seconds* relative to the most recent event."""
    if not events:
        return []
    cutoff = events[-1]["timestamp"] - timedelta(seconds=seconds)
    return [e for e in events if e["timestamp"] >= cutoff]


# ── Individual detection rules ─────────────────────────────────────────

def detect_port_scan(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect port scanning: many distinct destination ports from one source IP."""
    findings: list[dict[str, Any]] = []
    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        by_src[e["source_ip"]].append(e)

    threshold = settings.port_scan_threshold
    window_sec = settings.port_scan_window_seconds

    for src_ip, src_events in by_src.items():
        recent = _window(src_events, window_sec)
        dest_ports = {
            e["destination_port"]
            for e in recent
            if e.get("destination_port") is not None
        }
        if len(dest_ports) >= threshold:
            severity = "high" if len(dest_ports) >= threshold * 2 else "medium"
            findings.append({
                "incident_type": INCIDENT_PORT_SCAN,
                "severity": severity,
                "confidence": min(1.0, len(dest_ports) / (threshold * 3)),
                "source_ip": src_ip,
                "destination_ip": None,
                "evidence": [
                    f"Scanned {len(dest_ports)} distinct ports in {window_sec}s window",
                    f"Ports: {sorted(dest_ports)[:20]}",
                    f"Total events in window: {len(recent)}",
                ],
                "recommended_actions": [
                    "Add source IP to watchlist",
                    "Recommend firewall block for source IP",
                    "Collect full packet capture for analysis",
                    "Review affected services for exploitation attempts",
                ],
            })
    return findings


def detect_brute_force(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect SSH brute force: repeated failed logins from same source IP."""
    findings: list[dict[str, Any]] = []
    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        by_src[e["source_ip"]].append(e)

    threshold = settings.brute_force_threshold
    window_sec = settings.brute_force_window_seconds

    for src_ip, src_events in by_src.items():
        failed = [
            e for e in src_events
            if e.get("action") and "fail" in e["action"].lower()
            and e.get("event_type") in ("ssh", "auth", "login", "authentication")
        ]
        recent = _window(failed, window_sec)
        if len(recent) >= threshold:
            usernames = {e.get("username") for e in recent if e.get("username")}
            severity = "critical" if len(recent) >= threshold * 3 else "high"
            findings.append({
                "incident_type": INCIDENT_BRUTE_FORCE,
                "severity": severity,
                "confidence": min(1.0, len(recent) / (threshold * 5)),
                "source_ip": src_ip,
                "destination_ip": None,
                "evidence": [
                    f"{len(recent)} failed authentication attempts in {window_sec}s window",
                    f"Targeted usernames: {sorted(usernames)[:10]}",
                    f"Threshold: {threshold}",
                ],
                "recommended_actions": [
                    "Recommend firewall block for source IP",
                    "Recommend disabling targeted user accounts temporarily",
                    "Recommend enforcing MFA for targeted accounts",
                    "Collect authentication logs for forensic analysis",
                    "Recommend password reset for affected accounts",
                ],
            })
    return findings


def detect_web_attacks(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect web attack patterns in URLs."""
    if not settings.web_attack_patterns:
        return []
    findings: list[dict[str, Any]] = []

    for e in events:
        url = e.get("url") or ""
        if not url:
            continue
        matched_patterns: list[str] = []
        for pattern_name, regex in _WEB_ATTACK_PATTERNS:
            if regex.search(url):
                matched_patterns.append(pattern_name)
        if matched_patterns:
            findings.append({
                "incident_type": INCIDENT_WEB_ATTACK,
                "severity": "high" if len(matched_patterns) >= 2 else "medium",
                "confidence": min(1.0, 0.5 + 0.2 * len(matched_patterns)),
                "source_ip": e["source_ip"],
                "destination_ip": e.get("destination_ip"),
                "evidence": [
                    f"Suspicious URL: {url[:200]}",
                    f"Matched patterns: {matched_patterns}",
                    f"User-Agent: {e.get('user_agent', 'unknown')}",
                ],
                "recommended_actions": [
                    "Recommend blocking source IP at WAF/firewall",
                    "Review web server logs for successful exploitation",
                    "Recommend isolating affected web server",
                    "Check for data exfiltration from the target endpoint",
                    "Update WAF rules to block similar patterns",
                ],
            })
    return findings


def detect_data_exfiltration(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect possible data exfiltration: high outbound bytes."""
    findings: list[dict[str, Any]] = []
    by_dst: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        dst = e.get("destination_ip")
        if dst and not _is_private(dst):
            by_dst[dst].append(e)

    threshold_bytes = settings.exfil_threshold_mb * 1_048_576
    window_sec = settings.exfil_window_seconds

    for dst_ip, dst_events in by_dst.items():
        recent = _window(dst_events, window_sec)
        total_outbound = sum(e.get("bytes_out", 0) for e in recent)
        if total_outbound >= threshold_bytes:
            src_ips = {e["source_ip"] for e in recent}
            severity = "critical" if total_outbound >= threshold_bytes * 5 else "high"
            findings.append({
                "incident_type": INCIDENT_DATA_EXFIL,
                "severity": severity,
                "confidence": min(1.0, total_outbound / (threshold_bytes * 10)),
                "source_ip": ", ".join(sorted(src_ips)[:5]),
                "destination_ip": dst_ip,
                "evidence": [
                    f"Total outbound: {total_outbound:,} bytes ({total_outbound / 1_048_576:.1f} MB) in {window_sec}s",
                    f"Number of connections: {len(recent)}",
                    f"Source IPs involved: {len(src_ips)}",
                ],
                "recommended_actions": [
                    "Recommend isolating affected internal host(s)",
                    "Recommend collecting full packet capture",
                    "Recommend checking for data staging before exfiltration",
                    "Review DLP alerts for sensitive data types",
                    "Recommend credential rotation for affected systems",
                ],
            })
    return findings


def detect_c2_beaconing(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect C2-like beaconing: periodic connections to same external host."""
    findings: list[dict[str, Any]] = []
    by_dst: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        dst = e.get("destination_ip")
        if dst and not _is_private(dst):
            by_dst[dst].append(e)

    min_interval = settings.beacon_interval_min
    max_interval = settings.beacon_interval_max
    repeat_count = settings.beacon_repeat_count

    for dst_ip, dst_events in by_dst.items():
        if len(dst_events) < repeat_count:
            continue
        dst_events.sort(key=lambda e: e["timestamp"])
        intervals = []
        for i in range(1, len(dst_events)):
            delta = (dst_events[i]["timestamp"] - dst_events[i - 1]["timestamp"]).total_seconds()
            if min_interval <= delta <= max_interval:
                intervals.append(delta)
        if len(intervals) >= repeat_count - 1:
            avg_interval = sum(intervals) / len(intervals)
            src_ips = {e["source_ip"] for e in dst_events}
            user_agents = {e.get("user_agent") for e in dst_events if e.get("user_agent")}
            findings.append({
                "incident_type": INCIDENT_C2_BEACONING,
                "severity": "high",
                "confidence": min(1.0, len(intervals) / (repeat_count * 2)),
                "source_ip": ", ".join(sorted(src_ips)[:5]),
                "destination_ip": dst_ip,
                "evidence": [
                    f"{len(intervals)} periodic connections detected (avg interval: {avg_interval:.1f}s)",
                    f"Interval range: {min_interval}s–{max_interval}s",
                    f"Connection count: {len(dst_events)}",
                    f"User-Agents: {[ua[:50] for ua in user_agents if ua][:5]}",
                ],
                "recommended_actions": [
                    "Recommend blocking destination IP at firewall",
                    "Recommend isolating beaconing internal host(s)",
                    "Collect full packet capture for C2 traffic analysis",
                    "Check for malware persistence mechanisms",
                    "Recommend full endpoint scan on affected hosts",
                    "Review DNS queries for domain reputation",
                ],
            })
    return findings


def detect_ddos(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect DDoS/traffic flood: high request rate to one destination."""
    findings: list[dict[str, Any]] = []
    by_dst: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        dst = e.get("destination_ip")
        if dst:
            by_dst[dst].append(e)

    threshold = settings.flood_threshold
    window_sec = settings.flood_window_seconds

    for dst_ip, dst_events in by_dst.items():
        recent = _window(dst_events, window_sec)
        if len(recent) >= threshold:
            src_ips = {e["source_ip"] for e in recent}
            severity = "critical" if len(recent) >= threshold * 5 else "high"
            # Distinguish internal vs external target
            target_type = "internal service" if _is_private(dst_ip) else "external host"
            findings.append({
                "incident_type": INCIDENT_DDOS,
                "severity": severity,
                "confidence": min(1.0, len(recent) / (threshold * 10)),
                "source_ip": ", ".join(sorted(src_ips)[:10]),
                "destination_ip": dst_ip,
                "evidence": [
                    f"{len(recent)} events targeting {target_type} in {window_sec}s window",
                    f"Unique source IPs: {len(src_ips)}",
                    f"Threshold: {threshold}",
                ],
                "recommended_actions": [
                    "Recommend activating DDoS mitigation if available",
                    "Recommend rate-limiting at load balancer/WAF",
                    "Collect traffic flow data for analysis",
                    "Notify network operations team",
                    "Consider null-routing target IP if external",
                ],
            })
    return findings


def detect_policy_violations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect policy violations: access to blocked ports or restricted subnets."""
    findings: list[dict[str, Any]] = []
    for e in events:
        port = e.get("destination_port")
        if port is None:
            continue
        if port in _BLOCKED_PORTS:
            proto = e.get("protocol", "unknown")
            findings.append({
                "incident_type": INCIDENT_POLICY_VIOLATION,
                "severity": "medium",
                "confidence": 0.8,
                "source_ip": e["source_ip"],
                "destination_ip": e.get("destination_ip"),
                "evidence": [
                    f"Access to blocked port {port}/{proto}",
                    f"Blocked ports policy: {sorted(_BLOCKED_PORTS)[:10]}...",
                ],
                "recommended_actions": [
                    "Review access request for port",
                    "Recommend firewall rule enforcement",
                    "Notify security team of policy violation",
                ],
            })
    return findings


# ── Main entry point ────────────────────────────────────────────────────

def analyze_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run all detection rules against *events* and return findings."""
    if not events:
        return []

    all_findings: list[dict[str, Any]] = []
    all_findings += detect_port_scan(events)
    all_findings += detect_brute_force(events)
    all_findings += detect_web_attacks(events)
    all_findings += detect_data_exfiltration(events)
    all_findings += detect_c2_beaconing(events)
    all_findings += detect_ddos(events)
    all_findings += detect_policy_violations(events)

    log.info("Detection complete: %d findings from %d events", len(all_findings), len(events))
    return all_findings
