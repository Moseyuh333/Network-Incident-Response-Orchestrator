from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory


class NetworkIncidentPipelineTests(unittest.TestCase):
    def test_orchestrator_runs_parallel_stages_and_writes_structured_report(self) -> None:
        from app.orchestrator.pipeline import run_incident_pipeline

        alert = {
            "alert_id": "ALERT-09-001",
            "title": "Possible C2 beaconing and exfiltration",
            "source_ip": "10.10.5.23",
            "destination_ip": "203.0.113.77",
            "timestamp": datetime(2026, 6, 8, 8, 30, tzinfo=UTC).isoformat(),
            "severity": "high",
        }

        with TemporaryDirectory() as tmp:
            report = run_incident_pipeline(alert, output_dir=Path(tmp))

            self.assertEqual(report["alert"]["alert_id"], "ALERT-09-001")
            self.assertEqual(
                set(report["stage_1_collection"]),
                {"recon", "logs", "pcap_features"},
            )
            self.assertIn("incident_classification", report["stage_2_analysis"])
            self.assertGreaterEqual(report["stage_2_analysis"]["incident_classification"]["confidence"], 0.7)
            self.assertTrue(report["mitre_attack"])
            self.assertTrue(report["containment_plan"])
            self.assertTrue(report["ir_report_markdown"].endswith(".md"))

            report_path = Path(tmp) / "incident_report.json"
            self.assertTrue(report_path.exists())
            saved = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["pipeline"]["mode"], "parallel")

    def test_pi_artifact_generator_creates_required_submission_layout(self) -> None:
        from app.artifacts.pi_layout import create_pi_artifacts

        with TemporaryDirectory() as tmp:
            root = create_pi_artifacts(Path(tmp))

            expected = [
                root / "agents" / "incident-orchestrator-agent.md",
                root / "skills" / "network-ir-orchestrator" / "SKILL.md",
                root / "chains" / "network-ir-chain.md",
                root / "data" / "sample_alert.json",
                root / "logs" / "pipeline_audit.log",
                root / "triage" / "sample_triage.json",
                root / "results" / "ket-qua-topic-09.md",
            ]
            for path in expected:
                self.assertTrue(path.exists(), f"missing artifact: {path}")

    def test_docx_report_builder_writes_word_document(self) -> None:
        from app.artifacts.docx_report import build_submission_docx
        from app.orchestrator.pipeline import run_incident_pipeline

        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            report = run_incident_pipeline(
                {
                    "alert_id": "ALERT-09-DOCX",
                    "title": "DOCX report generation check",
                    "source_ip": "10.10.5.23",
                    "destination_ip": "203.0.113.77",
                    "severity": "high",
                },
                output_dir=tmp_path,
            )
            docx_path = build_submission_docx(report, tmp_path / "topic09-report.docx")

            self.assertTrue(docx_path.exists())
            self.assertGreater(docx_path.stat().st_size, 10_000)


if __name__ == "__main__":
    unittest.main()
