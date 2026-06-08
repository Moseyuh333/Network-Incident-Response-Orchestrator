"""Parallel incident-response pipeline implementation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from app.orchestrator.classifier import classify_incident, embedding_style_score
from app.orchestrator.collectors import collect_logs, collect_recon, extract_pcap_features
from app.orchestrator.mitre import build_containment_plan, map_to_mitre
from app.orchestrator.reporting import persist_reports, report_metadata

Collector = Callable[[dict[str, Any]], dict[str, Any]]


def _timed_task(task: Collector, alert: dict[str, Any]) -> tuple[dict[str, Any], float]:
    started = perf_counter()
    result = task(alert)
    return result, round(perf_counter() - started, 6)


def _run_parallel_tasks(
    tasks: dict[str, Collector],
    alert: dict[str, Any],
    max_workers: int,
) -> tuple[dict[str, Any], dict[str, float]]:
    results: dict[str, Any] = {}
    timings: dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_timed_task, task, alert): name
            for name, task in tasks.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            result, elapsed = future.result()
            results[name] = result
            timings[name] = elapsed
    return results, timings


def run_incident_pipeline(
    alert: dict[str, Any],
    output_dir: str | Path,
    *,
    max_workers: int = 3,
) -> dict[str, Any]:
    """Run the full incident-response pipeline and persist JSON/Markdown outputs."""
    output_path = Path(output_dir)
    pipeline_started = perf_counter()
    normalized_alert = {
        "alert_id": alert.get("alert_id", "ALERT-09-DEMO"),
        "title": alert.get("title", "Network security alert"),
        "source_ip": alert.get("source_ip", "10.10.5.23"),
        "destination_ip": alert.get("destination_ip", "203.0.113.77"),
        "timestamp": alert.get("timestamp")
        or datetime.now(UTC).replace(microsecond=0).isoformat(),
        "severity": alert.get("severity", "high"),
    }

    stage_1_tasks: dict[str, Collector] = {
        "recon": collect_recon,
        "logs": collect_logs,
        "pcap_features": extract_pcap_features,
    }
    stage_1, stage_1_timings = _run_parallel_tasks(stage_1_tasks, normalized_alert, max_workers)

    def classify(_: dict[str, Any]) -> dict[str, Any]:
        return classify_incident(stage_1, normalized_alert)

    def score(_: dict[str, Any]) -> dict[str, Any]:
        return {"profile_scores": embedding_style_score(stage_1)}

    stage_2, stage_2_timings = _run_parallel_tasks(
        {
            "incident_classification": classify,
            "embedding_profile_score": score,
        },
        normalized_alert,
        max_workers=2,
    )
    classification = stage_2["incident_classification"]
    mitre_mapping = map_to_mitre(classification)
    containment_plan = build_containment_plan(normalized_alert, classification)

    report: dict[str, Any] = {
        "metadata": report_metadata(),
        "alert": normalized_alert,
        "pipeline": {
            "topic": "Topic 09 - Network Incident Response Orchestrator",
            "mode": "parallel",
            "elapsed_seconds": round(perf_counter() - pipeline_started, 6),
            "stage_1_timings": stage_1_timings,
            "stage_2_timings": stage_2_timings,
        },
        "stage_1_collection": stage_1,
        "stage_2_analysis": stage_2,
        "mitre_attack": mitre_mapping,
        "containment_plan": containment_plan,
    }
    paths = persist_reports(report, output_path)
    report["ir_report_json"] = paths["json"]
    report["ir_report_markdown"] = paths["markdown"]
    persist_reports(report, output_path)
    return report
