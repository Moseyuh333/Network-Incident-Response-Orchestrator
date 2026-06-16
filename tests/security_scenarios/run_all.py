"""One-shot runner for the security scenario suite.

Walks the registry, runs every scenario through the real ingestion
pipeline, prints a coverage report, and writes a JSON report to
``results/last_run.json`` for diffing across runs.

Usage:
    python tests/security_scenarios/run_all.py
    python tests/security_scenarios/run_all.py --only s05 s17
    python tests/security_scenarios/run_all.py --category detect
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Ensure both the project root (so `app` is importable) and the security_scenarios
# package parent are on sys.path, regardless of how this script is invoked.
_PROJECT_ROOT = HERE.parent.parent
for p in (str(_PROJECT_ROOT), str(HERE.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from tests.security_scenarios import REGISTRY, ScenarioCategory, Verdict  # noqa: E402


_VERDICT_GLYPH = {
    Verdict.DETECTED: "✅",
    Verdict.PARTIAL: "🟡",
    Verdict.MISSED: "🔴",
    Verdict.FALSE_POSITIVE: "⚪",
    Verdict.CLEAN: "✅",
    Verdict.KNOWN_GAP: "🟣",
}


def _filter_registry(
    registry: list, only: list[str] | None, category: str | None
) -> list:
    selected = list(registry)
    if only:
        only_set: set[str] = set()
        for n in only:
            n = n.lower()
            if not n.startswith("s"):
                n = f"s{int(n):02d}"  # allow "5" → "s05"
            only_set.add(n)
        selected = [s for s in selected if s.id in only_set]
    if category:
        cat = ScenarioCategory(category)
        selected = [s for s in selected if s.expectation.category is cat]
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the N.I.R.O. security scenario suite")
    parser.add_argument("--only", nargs="+", help="Run only these scenario ids (e.g. s05 s17)")
    parser.add_argument(
        "--category",
        choices=[c.value for c in ScenarioCategory],
        help="Filter by scenario category",
    )
    parser.add_argument("--no-write", action="store_true", help="Skip writing the JSON report")
    args = parser.parse_args()

    selected = _filter_registry(REGISTRY, args.only, args.category)
    if not selected:
        print("No scenarios selected.")
        return 1

    print(f"Running {len(selected)} scenario(s)...\n")
    started = time.monotonic()
    results = []
    for scenario_cls in selected:
        scenario = scenario_cls()
        result = scenario.run()
        results.append(result)
        glyph = _VERDICT_GLYPH[result.verdict]
        notes = f"  — {result.expectation.notes[:80]}" if result.expectation.notes else ""
        findings_summary = ", ".join(f["incident_type"] for f in result.actual_findings) or "(none)"
        print(
            f"  {glyph} {result.expectation.id} {result.expectation.title}\n"
            f"     category={result.expectation.category.value} "
            f"events={result.events_ingested} "
            f"matched={result.matched or '∅'} "
            f"actual=[{findings_summary}] "
            f"({result.duration_seconds:.2f}s){notes}"
        )
        if result.error:
            print(f"     ⚠️  ERROR: {result.error}")
        print()

    # Coverage report
    total = len(results)
    by_verdict = Counter(r.verdict for r in results)
    by_category: dict[str, Counter] = {}
    for r in results:
        by_category.setdefault(r.expectation.category.value, Counter())[r.verdict] += 1

    elapsed = time.monotonic() - started
    print("─" * 78)
    print(f"Coverage report ({elapsed:.2f}s total):\n")
    for cat, counts in sorted(by_category.items()):
        cat_total = sum(counts.values())
        print(f"  {cat.upper():14s} {cat_total:3d} scenarios  " + "  ".join(
            f"{v.value}={c}" for v, c in sorted(counts.items(), key=lambda kv: -kv[1])
        ))
    print(f"\n  TOTAL: {total} scenarios")
    print(f"    Detected:           {by_verdict[Verdict.DETECTED]:3d}")
    print(f"    Partial (some hits):{by_verdict[Verdict.PARTIAL]:3d}")
    print(f"    Missed (true pos):  {by_verdict[Verdict.MISSED]:3d}")
    print(f"    Clean (true neg):   {by_verdict[Verdict.CLEAN]:3d}")
    print(f"    False positive:     {by_verdict[Verdict.FALSE_POSITIVE]:3d}")
    print(f"    Known gap:          {by_verdict[Verdict.KNOWN_GAP]:3d}")

    if not args.no_write:
        results_dir = HERE / "results"
        results_dir.mkdir(exist_ok=True)
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(elapsed, 3),
            "summary": {v.value: c for v, c in by_verdict.items()},
            "results": [r.to_dict() for r in results],
        }
        report_path = results_dir / "last_run.json"
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nReport written to {report_path}")

    # Exit code: 0 if no missed detections and no false positives; 1 otherwise.
    # Use this with CI to fail the build on coverage regression.
    bad = by_verdict[Verdict.MISSED] + by_verdict[Verdict.FALSE_POSITIVE]
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
