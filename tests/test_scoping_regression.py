from __future__ import annotations

import json

from app.agents.incident_response_agent import IncidentResponseAgent
from app.core.paths import PI_DIR
from app.llm.providers import LLMResult
import scripts.run_pipeline as pipeline


class OfflineProvider:
    provider_name = "offline-test"
    model = "offline"

    def generate_json(self, prompt: str, response_schema: dict):
        return LLMResult(False, self.provider_name, self.model, fallback_reason="offline")


def test_unrelated_critical_event_does_not_change_alert_classification(tmp_path, monkeypatch) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    alert = {
        "alert_id": "ALERT-SCOPE-001",
        "timestamp": "2026-06-05T15:20:00Z",
        "source_ip": "203.0.113.77",
        "destination_ip": "10.10.20.15",
        "summary": "Web payload against web server",
    }
    events = [
        {
            "timestamp": "2026-06-05T15:19:03Z",
            "event_type": "web",
            "source_ip": "203.0.113.77",
            "destination_ip": "10.10.20.15",
            "source_port": 50202,
            "destination_port": 80,
            "protocol": "HTTP",
            "action": "allowed",
            "url": "/download?file=../../../../etc/passwd",
            "bytes_in": 600,
            "bytes_out": 4096,
        },
        {
            "timestamp": "2026-06-05T15:20:00Z",
            "event_type": "ssh",
            "source_ip": "198.51.100.10",
            "destination_ip": "10.10.30.30",
            "source_port": 51000,
            "destination_port": 22,
            "protocol": "TCP",
            "action": "failed_login",
            "username": "root",
            "bytes_in": 10,
            "bytes_out": 1,
        },
    ]
    for i in range(20):
        event = dict(events[-1])
        event["timestamp"] = f"2026-06-05T15:20:{i:02d}Z"
        event["source_port"] = 51000 + i
        events.append(event)

    (data_dir / "sample_alert.json").write_text(json.dumps(alert), encoding="utf-8")
    (data_dir / "security_events.json").write_text(json.dumps({"events": events}), encoding="utf-8")
    (data_dir / "asset_inventory.json").write_text(
        json.dumps({"assets": [{"ip": "10.10.20.15", "criticality": "high", "internet_facing": True}]}),
        encoding="utf-8",
    )
    (data_dir / "pcap_features.json").write_text(json.dumps({"flows": []}), encoding="utf-8")
    import app.core.paths as paths
    monkeypatch.setattr(paths, "DATA_DIR", data_dir)

    triage = pipeline.run_pipeline(
        data_dir / "sample_alert.json",
        output_dir=tmp_path / "out",
        agent=IncidentResponseAgent(PI_DIR, provider=OfflineProvider()),
    )

    assert triage["classification"]["label"] == "Web Attack"
    assert all(f["source_ip"] != "198.51.100.10" for f in triage["stage_1"]["logs"]["findings"])
