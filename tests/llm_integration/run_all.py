"""One-shot runner for the LLM integration test suite.

Default-off to protect API quota. Set ``RUN_LLM_TESTS=1`` to actually
hit the LLM.

    RUN_LLM_TESTS=1 python -m tests.llm_integration.run_all
    RUN_LLM_TESTS=1 python -m tests.llm_integration.run_all --only s02 s05
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = HERE.parent.parent
for p in (str(_PROJECT_ROOT), str(HERE.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.llm.providers import GoogleGenAIProvider  # noqa: E402
from tests.llm_integration.llm_runner import run_llm_for_scenario  # noqa: E402


# ── Scenario catalogue ──────────────────────────────────────────────
# Each entry: scenario_id, expected incident type, representative evidence
# the LLM will see. Keep this small and representative — one per detector
# family — to stay within API quota.

LLM_SCENARIOS: list[dict] = [
    {
        "id": "s02",
        "title": "SSH brute force",
        "expected_type": "Brute Force",
        "evidence": {
            "source_ip": "198.51.100.50",
            "destination_ip": "10.10.20.5",
            "destination_port": 22,
            "severity": "high",
            "confidence": 0.85,
            "summary": (
                "6 failed SSH login attempts targeting the 'root' account from "
                "198.51.100.50 in 60 seconds."
            ),
            "evidence": [
                "Failed authentication events: 6",
                "Source IP: 198.51.100.50",
                "Targeted account: root",
                "Window: 60 seconds",
            ],
        },
        "assertions": {
            "expect_mitre": True,
            "expect_actions": True,
            "min_confidence": 0.5,
        },
    },
    {
        "id": "s03",
        "title": "SQL injection",
        "expected_type": "Web Attack",
        "evidence": {
            "source_ip": "198.51.100.60",
            "destination_ip": "10.10.20.10",
            "destination_port": 80,
            "severity": "high",
            "confidence": 0.9,
            "summary": (
                "SQL injection attempt via /api/users?id=1%27%20UNION%20SELECT "
                "against web server 10.10.20.10."
            ),
            "evidence": [
                "Suspicious URL: /api/users?id=1' UNION SELECT * FROM admin--",
                "User-Agent: sqlmap/1.7",
                "Matched patterns: SQL Injection (UNION/select)",
            ],
        },
        "assertions": {
            "expect_mitre": True,
            "expect_actions": True,
            "min_confidence": 0.5,
        },
    },
    {
        "id": "s04",
        "title": "Data exfiltration",
        "expected_type": "Data Exfiltration",
        "evidence": {
            "source_ip": "10.10.20.22",
            "destination_ip": "198.51.100.200",
            "destination_port": 443,
            "severity": "high",
            "confidence": 0.8,
            "summary": (
                "60MB outbound transfer from internal host 10.10.20.22 to "
                "external IP 198.51.100.200 over HTTPS within 60 seconds."
            ),
            "evidence": [
                "Total outbound: 60MB in 60s",
                "Source: 10.10.20.22 (internal)",
                "Destination: 198.51.100.200 (public)",
                "Protocol: HTTPS/443",
            ],
        },
        "assertions": {
            "expect_mitre": True,
            "expect_actions": True,
            "min_confidence": 0.5,
        },
    },
    {
        "id": "s05",
        "title": "C2 beaconing",
        "expected_type": "C2 Beaconing",
        "evidence": {
            "source_ip": "10.10.20.30",
            "destination_ip": "198.51.100.210",
            "destination_port": 443,
            "severity": "high",
            "confidence": 0.9,
            "summary": (
                "7 periodic HTTPS connections from 10.10.20.30 to "
                "198.51.100.210 every 15 seconds with low jitter."
            ),
            "evidence": [
                "Connection count: 7",
                "Average interval: 15.0s",
                "Jitter: 0.0s",
                "User-Agent: CobaltStrike beacon",
            ],
        },
        "assertions": {
            "expect_mitre": True,
            "expect_actions": True,
            "min_confidence": 0.5,
        },
    },
    {
        "id": "s18",
        "title": "Webshell activity",
        "expected_type": "Web Attack",
        "evidence": {
            "source_ip": "198.51.100.99",
            "destination_ip": "10.10.20.50",
            "destination_port": 80,
            "severity": "critical",
            "confidence": 0.95,
            "summary": (
                "Webshell command execution detected on /uploads/shell.php "
                "with ;id and |whoami patterns."
            ),
            "evidence": [
                "URL: /uploads/shell.php?cmd=;id",
                "URL: /uploads/shell.php?cmd=|whoami",
                "User-Agent: curl/8.0",
            ],
        },
        "assertions": {
            "expect_mitre": True,
            "expect_actions": True,
            "min_confidence": 0.6,
        },
    },
    {
        "id": "s22",
        "title": "Multi-stage attack (full intrusion)",
        "expected_type": "Web Attack",
        "evidence": {
            "source_ip": "198.51.100.123",
            "destination_ip": "10.10.20.100",
            "destination_port": 443,
            "severity": "critical",
            "confidence": 0.95,
            "summary": (
                "Multi-stage intrusion observed: external port scan (12 "
                "ports in 60s), SQL injection at /api/users, 80MB outbound "
                "exfil to 198.51.100.220, and 7 C2 beacons to same host. "
                "Stages: Recon → Initial Access → Exfiltration → C2."
            ),
            "evidence": [
                "Stage 1: Port scan 12 distinct ports",
                "Stage 2: SQL injection via UNION SELECT",
                "Stage 3: 80MB outbound to 198.51.100.220",
                "Stage 4: 7 C2 beacons every 30s",
            ],
        },
        "assertions": {
            "expect_mitre": True,
            "expect_actions": True,
            "min_confidence": 0.7,
        },
    },
]


def _filter_scenarios(specs: list[dict], only: list[str] | None) -> list[dict]:
    if not only:
        return list(specs)
    wanted = set(only)
    return [s for s in specs if s["id"] in wanted]


def _assert_scenario(analysis, spec: dict) -> tuple[bool, list[str]]:
    """Check the LLM analysis against the expected contract. Returns (ok, notes)."""
    notes: list[str] = []
    if not analysis.available:
        notes.append(f"LLM unavailable: {analysis.fallback_reason or analysis.error}")
        return False, notes
    if analysis.error:
        notes.append(f"Error: {analysis.error}")
        return False, notes
    if analysis.parsed is None:
        notes.append("Parsed output is None — likely schema mismatch")
        return False, notes

    parsed = analysis.parsed
    expected = spec["assertions"]
    ok = True

    # Type agreement
    if parsed.incident_type and spec["expected_type"].lower() not in parsed.incident_type.lower():
        notes.append(
            f"Type mismatch: LLM said '{parsed.incident_type}', expected '{spec['expected_type']}'"
        )
        ok = False
    else:
        notes.append(f"Type: {parsed.incident_type!r} ✓")

    # Confidence
    if parsed.confidence < expected.get("min_confidence", 0.0):
        notes.append(f"Confidence {parsed.confidence} below expected {expected['min_confidence']}")
        ok = False
    else:
        notes.append(f"Confidence: {parsed.confidence:.2f} ✓")

    # MITRE
    if expected.get("expect_mitre") and not parsed.mitre_mapping:
        notes.append("No MITRE mapping returned — expected at least one technique")
        ok = False
    elif parsed.mitre_mapping:
        ids = ", ".join(m.technique_id for m in parsed.mitre_mapping)
        notes.append(f"MITRE: {ids} ✓")

    # Recommended actions
    if expected.get("expect_actions") and not parsed.recommended_actions:
        notes.append("No recommended actions returned")
        ok = False
    elif parsed.recommended_actions:
        actions = ", ".join(a.action for a in parsed.recommended_actions[:3])
        notes.append(f"Actions: {actions}{'...' if len(parsed.recommended_actions) > 3 else ''} ✓")

    # Latency budget
    if analysis.latency_seconds > 30.0:
        notes.append(f"Slow: {analysis.latency_seconds:.1f}s (budget 30s)")
        ok = False
    else:
        notes.append(f"Latency: {analysis.latency_seconds:.1f}s ✓")

    return ok, notes


def main() -> int:
    parser = argparse.ArgumentParser(description="Run LLM integration tests")
    parser.add_argument("--only", nargs="+", help="Run only these scenario ids")
    parser.add_argument("--no-write", action="store_true", help="Skip writing JSON report")
    args = parser.parse_args()

    if not os.environ.get("RUN_LLM_TESTS"):
        print(
            "LLM tests are off by default to protect API quota.\n"
            "Set RUN_LLM_TESTS=1 to actually call the LLM. Example:\n"
            "    RUN_LLM_TESTS=1 python -m tests.llm_integration.run_all\n"
            "Or run the cheap probe first:\n"
            "    python -m tests.llm_integration.probe"
        )
        return 0

    provider = GoogleGenAIProvider()
    if not provider.is_configured:
        print("LLM provider is not configured. Set LLM_API_KEY in .env first.")
        return 1

    selected = _filter_scenarios(LLM_SCENARIOS, args.only)
    if not selected:
        print("No scenarios selected.")
        return 1

    print(f"LLM: {provider.provider_name} / {provider.model}")
    print(f"Running {len(selected)} scenario(s) — this will cost API quota.\n")
    started = time.monotonic()
    results = []
    passed = 0
    for spec in selected:
        print(f"  ▶ {spec['id']} {spec['title']} (expected: {spec['expected_type']})")
        analysis = run_llm_for_scenario(
            spec["id"], spec["expected_type"], spec["evidence"], provider=provider
        )
        ok, notes = _assert_scenario(analysis, spec)
        results.append({"spec": spec, "analysis": analysis.to_dict(), "ok": ok, "notes": notes})
        passed += 1 if ok else 0
        glyph = "✅" if ok else "❌"
        for line in notes:
            print(f"     {glyph if ok else '⚠️ '} {line}")
        print()

    elapsed = time.monotonic() - started
    print("─" * 78)
    print(f"LLM integration report ({elapsed:.1f}s total):")
    print(f"  Passed: {passed}/{len(selected)}")
    print(f"  Latency: each call costs ~2-30s depending on model and load")

    if not args.no_write:
        results_dir = HERE / "results"
        results_dir.mkdir(exist_ok=True)
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": provider.provider_name,
            "model": provider.model,
            "passed": passed,
            "total": len(selected),
            "results": results,
        }
        report_path = results_dir / "last_run.json"
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nReport written to {report_path}")

    return 0 if passed == len(selected) else 1


if __name__ == "__main__":
    sys.exit(main())
