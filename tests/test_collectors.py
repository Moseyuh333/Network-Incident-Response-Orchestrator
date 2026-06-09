from __future__ import annotations

import json

from app.collectors.suricata import parse_eve_file
from app.collectors.zeek import parse_zeek_file


def test_suricata_eve_parser_preserves_flow_id(tmp_path) -> None:
    path = tmp_path / "eve.json"
    path.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-05T15:00:00Z",
                "event_type": "http",
                "flow_id": 123,
                "src_ip": "203.0.113.1",
                "dest_ip": "10.10.20.15",
                "src_port": 50000,
                "dest_port": 80,
                "proto": "TCP",
                "http": {"url": "/index.php?id=1%27%20or%201=1", "http_user_agent": "curl"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = parse_eve_file(path)

    assert events[0].source_type == "suricata"
    assert events[0].flow_id == "123"
    assert events[0].url.startswith("/index")


def test_zeek_parser_maps_conn_record(tmp_path) -> None:
    path = tmp_path / "conn.log"
    path.write_text(
        json.dumps(
            {
                "ts": 1780671600.0,
                "uid": "C1",
                "id.orig_h": "10.10.20.15",
                "id.orig_p": 44444,
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 443,
                "proto": "tcp",
                "conn_state": "SF",
                "orig_bytes": 10,
                "resp_bytes": 20,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = parse_zeek_file(path)

    assert events[0].source_type == "zeek"
    assert events[0].flow_id == "C1"
    assert events[0].destination_port == 443
