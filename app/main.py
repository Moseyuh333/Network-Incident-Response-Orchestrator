"""Command-line entry point for the Network IR Orchestrator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app.artifacts.docx_report import build_submission_docx
from app.artifacts.pi_layout import SAMPLE_ALERT, create_pi_artifacts
from app.orchestrator.pipeline import run_incident_pipeline


def _load_alert(path: Path | None) -> dict[str, Any]:
    if path is None:
        return dict(SAMPLE_ALERT)
    return json.loads(path.read_text(encoding="utf-8"))


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Network Incident Response Orchestrator")
    parser.add_argument(
        "--alert",
        type=Path,
        default=None,
        help="Path to alert JSON. Defaults to the built-in Topic 09 sample alert.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".pi/outputs/demo"),
        help="Directory for pipeline JSON/Markdown outputs.",
    )
    parser.add_argument(
        "--docx",
        type=Path,
        default=Path("reports/Topic_09_Network_IR_Orchestrator_Report.docx"),
        help="Path for the generated DOCX report.",
    )
    parser.add_argument(
        "--skip-pi",
        action="store_true",
        help="Do not regenerate the .pi submission artifact tree.",
    )
    args = parser.parse_args(argv)

    if not args.skip_pi:
        create_pi_artifacts(Path.cwd())
    report = run_incident_pipeline(_load_alert(args.alert), args.output)
    docx_path = build_submission_docx(report, args.docx)

    print(f"JSON report: {report['ir_report_json']}")
    print(f"Markdown report: {report['ir_report_markdown']}")
    print(f"DOCX report: {docx_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
