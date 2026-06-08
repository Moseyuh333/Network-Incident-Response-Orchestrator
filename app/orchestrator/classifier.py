"""Deterministic ML-style scoring for network incident triage."""

from __future__ import annotations

from collections import Counter
from typing import Any


PROFILES: dict[str, dict[str, Any]] = {
    "c2_beaconing": {
        "label": "C2 Beaconing with Data Exfiltration",
        "keywords": {
            "beacon",
            "periodic",
            "external",
            "tls",
            "suspicious",
            "rclone",
            "sync",
            "bytes",
            "exfiltration",
        },
        "mitre": ["T1071.001", "T1041", "T1105"],
    },
    "brute_force": {
        "label": "Credential Brute Force",
        "keywords": {"failed", "ssh", "login", "password", "username", "auth"},
        "mitre": ["T1110"],
    },
    "web_attack": {
        "label": "Web Application Attack",
        "keywords": {"sql", "injection", "traversal", "xss", "waf", "url"},
        "mitre": ["T1190"],
    },
    "port_scan": {
        "label": "Port Scanning and Service Discovery",
        "keywords": {"syn", "ports", "scan", "open", "service", "enumeration"},
        "mitre": ["T1046"],
    },
}


def _tokenize(value: Any) -> Counter[str]:
    text = str(value).lower()
    token = ""
    tokens: Counter[str] = Counter()
    for char in text:
        if char.isalnum():
            token += char
        elif token:
            tokens[token] += 1
            token = ""
    if token:
        tokens[token] += 1
    return tokens


def embedding_style_score(stage_1: dict[str, Any]) -> list[dict[str, Any]]:
    """Score stage-1 evidence against small incident profiles."""
    corpus_tokens = _tokenize(stage_1)
    scored: list[dict[str, Any]] = []
    for profile_id, profile in PROFILES.items():
        keywords = profile["keywords"]
        overlap = sum(1 for word in keywords if corpus_tokens[word] > 0)
        score = round(overlap / max(len(keywords), 1), 3)
        scored.append(
            {
                "profile_id": profile_id,
                "label": profile["label"],
                "score": score,
                "matched_keywords": sorted(word for word in keywords if corpus_tokens[word] > 0),
            }
        )
    return sorted(scored, key=lambda item: item["score"], reverse=True)


def classify_incident(stage_1: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    """Classify the incident using heuristic features and profile scoring."""
    pcap = stage_1["pcap_features"]
    logs = stage_1["logs"]
    recon = stage_1["recon"]
    profile_scores = embedding_style_score(stage_1)

    total_out = int(pcap.get("total_bytes_out", 0))
    interval = float(pcap.get("avg_beacon_interval_seconds") or 999.0)
    reputation = recon.get("destination", {}).get("reputation", "unknown")
    process_names = {
        name.lower()
        for name in recon.get("source_host", {}).get("observed_processes", [])
    }
    has_suspicious_process = "rclone.exe" in process_names
    has_beaconing = 5 <= interval <= 60 and int(pcap.get("flow_count", 0)) >= 6
    has_exfil = total_out >= 50 * 1_048_576
    has_suspicious_destination = reputation in {"suspicious", "malicious"}

    confidence = 0.45
    reasons = []
    if has_beaconing:
        confidence += 0.16
        reasons.append("Regular outbound beacon interval detected")
    if has_exfil:
        confidence += 0.16
        reasons.append("Outbound transfer exceeds exfiltration threshold")
    if has_suspicious_destination:
        confidence += 0.11
        reasons.append("Destination reputation is suspicious")
    if has_suspicious_process:
        confidence += 0.08
        reasons.append("Endpoint process list contains rclone.exe")
    if logs.get("event_count", 0) >= 10:
        confidence += 0.04
        reasons.append("Corroborating proxy/firewall/EDR events available")

    top_profile = profile_scores[0]
    return {
        "incident_type": top_profile["label"],
        "severity": "critical" if has_exfil and has_beaconing else alert.get("severity", "high"),
        "confidence": round(min(confidence, 0.98), 2),
        "model": "offline-weighted-feature-classifier-v1",
        "profile_scores": profile_scores,
        "reasoning_summary": reasons,
    }
