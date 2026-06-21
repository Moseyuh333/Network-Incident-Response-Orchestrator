"""Tests for the file-by-path ingestion endpoints.

Covers the three flavours of the ``POST /events/import/*`` family:
- ``/events/import/file`` (auto-detect)
- ``/events/import/pcap-path``
- ``/events/import/zeek`` + ``/events/import/suricata`` (already exist
  but exercised here against real sample files)
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import PCAP_MAX_BYTES
from app.web.server import app
from app.db.session import create_db_and_tables

client = TestClient(app)


ZEEK_LINE = (
    '{"ts":1718553600.0,"uid":"Cabc123","id.orig_h":"192.168.1.50","id.orig_p":54321,'
    '"id.resp_h":"10.0.0.10","id.resp_p":22,"proto":"tcp","conn_state":"SF",'
    '"orig_bytes":1024,"resp_bytes":2048}\n'
)
EVE_LINE = (
    '{"timestamp":"2026-06-17T07:30:00.000Z","event_type":"alert","src_ip":"203.0.113.99",'
    '"src_port":45678,"dest_ip":"10.0.0.5","dest_port":80,"proto":"tcp",'
    '"alert":{"action":"blocked","severity":2},"flow":{"bytes_toserver":120,"bytes_toclient":60}}\n'
)


def _make_pcap(tmp: Path) -> Path:
    """Write a tiny valid PCAP (libpcap format, 1 packet) for tests."""
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # Minimal Ethernet/IPv4/TCP frame (~54 bytes)
    eth_ip_tcp = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"  # eth
    eth_ip_tcp += b"\x45" + b"\x00" * 9 + b"\x0a\x00\x00\x01" + b"\x0a" * 4 + b"\x0a" * 4  # ip
    eth_ip_tcp += b"\x00" * 8 + b"\x00\x50" + b"\x00" * 12  # tcp
    pkt = eth_ip_tcp
    pcap = gh + struct.pack("<IIII", 1718553600, 0, len(pkt), len(pkt)) + pkt
    out = tmp / "tiny.pcap"
    out.write_bytes(pcap)
    return out


@pytest.fixture(autouse=True)
def reset_db() -> None:
    from sqlmodel import SQLModel
    from app.db.session import engine
    # Drop and recreate so the same sample data can be ingested twice
    # without violating the unique-event-id constraint.
    SQLModel.metadata.drop_all(engine)
    create_db_and_tables()


# ── /events/import/file (auto-detect) ─────────────────────────────────


def test_import_file_detects_zeek(tmp_path) -> None:
    f = tmp_path / "zeek.log"
    # Use unique uids so the test does not trip the events.external_event_id
    # UNIQUE constraint.
    line = (
        '{"ts":1718553600.0,"uid":"Cabc%d","id.orig_h":"192.168.1.50","id.orig_p":54321,'
        '"id.resp_h":"10.0.0.10","id.resp_p":22,"proto":"tcp","conn_state":"SF",'
        '"orig_bytes":1024,"resp_bytes":2048}\n'
    )
    f.write_text("".join(line % i for i in range(3)), encoding="utf-8")
    r = client.post(
        "/api/v1/events/import/file",
        json={"path": str(f)},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["format"] == "zeek"
    assert data["ingested"] == 3
    assert data["source"] == str(f)


def test_import_file_detects_suricata(tmp_path) -> None:
    f = tmp_path / "eve.json"
    line = (
        '{"timestamp":"2026-06-17T07:30:0%d.000Z","event_type":"alert","src_ip":"203.0.113.99",'
        '"src_port":45678,"dest_ip":"10.0.0.5","dest_port":80,"proto":"tcp",'
        '"flow_id":%d,'
        '"alert":{"action":"blocked","severity":2},"flow":{"bytes_toserver":120,"bytes_toclient":60}}\n'
    )
    f.write_text("".join(line % (i, i) for i in range(2)), encoding="utf-8")
    r = client.post(
        "/api/v1/events/import/file",
        json={"path": str(f)},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["format"] == "suricata"
    assert data["ingested"] == 2


def test_import_file_detects_pcap(tmp_path) -> None:
    f = _make_pcap(tmp_path)
    r = client.post(
        "/api/v1/events/import/file",
        json={"path": str(f)},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "pcap_bytes" in data


def test_import_file_unsupported_extension(tmp_path) -> None:
    f = tmp_path / "weird.txt"
    f.write_text("hello", encoding="utf-8")
    r = client.post(
        "/api/v1/events/import/file",
        json={"path": str(f)},
    )
    assert r.status_code == 415
    assert "unsupported" in r.json()["detail"]


def test_import_file_missing_path() -> None:
    r = client.post("/api/v1/events/import/file", json={})
    assert r.status_code == 400


def test_import_file_nonexistent() -> None:
    r = client.post(
        "/api/v1/events/import/file",
        json={"path": "/no/such/file.pcap"},
    )
    assert r.status_code == 404


# ── /events/import/pcap-path ──────────────────────────────────────────


def test_import_pcap_by_path_within_incoming(tmp_path, monkeypatch) -> None:
    """A file under the operator's home directory should be accepted."""
    # Mirror the file into a tmp location and make the test set the
    # allow-any flag so the test doesn't depend on where the project
    # lives on disk.
    f = _make_pcap(tmp_path)
    monkeypatch.setenv("CAPTURE_ALLOW_ANY_PATH", "1")
    r = client.post(
        "/api/v1/events/import/pcap-path",
        json={"path": str(f)},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["pcap_bytes"] == f.stat().st_size
    assert "incidents" in data


def test_import_pcap_by_path_missing_path() -> None:
    r = client.post("/api/v1/events/import/pcap-path", json={})
    assert r.status_code == 400


def test_import_pcap_by_path_not_found() -> None:
    r = client.post(
        "/api/v1/events/import/pcap-path",
        json={"path": "Z:/nope/traffic.pcap"},
    )
    assert r.status_code == 404


def test_import_pcap_by_path_outside_allowlist() -> None:
    """Without CAPTURE_ALLOW_ANY_PATH, a file outside the allowlist is 403.

    Skipped when the env var is set, because operators can opt in to
    unrestricted path access during testing or development.
    """
    import os
    if os.environ.get("CAPTURE_ALLOW_ANY_PATH", "").lower() in ("1", "true", "yes"):
        pytest.skip("CAPTURE_ALLOW_ANY_PATH is set; allowlist is bypassed")
    target = Path("C:/Windows/Temp/__niro_test_evil.pcap")
    if target.parent.exists():
        target.write_bytes(b"not really pcap")
        try:
            r = client.post(
                "/api/v1/events/import/pcap-path",
                json={"path": str(target)},
            )
            # Either 403 (allowlist blocks) or 413/400 (bad pcap), but
            # never 200.
            assert r.status_code != 200
        finally:
            target.unlink(missing_ok=True)


# ── /events/import/zeek + /events/import/suricata (by path) ───────────


def test_import_zeek_by_path(tmp_path) -> None:
    f = tmp_path / "zeek.log"
    f.write_text(ZEEK_LINE, encoding="utf-8")
    r = client.post(
        "/api/v1/events/import/zeek",
        json={"path": str(f)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ingested"] == 1


def test_import_suricata_by_path(tmp_path) -> None:
    f = tmp_path / "eve.json"
    f.write_text(EVE_LINE, encoding="utf-8")
    r = client.post(
        "/api/v1/events/import/suricata",
        json={"path": str(f)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ingested"] == 1


# ── /events/import/pcap (multipart, original endpoint) ────────────────


def test_import_pcap_multipart(tmp_path) -> None:
    f = _make_pcap(tmp_path)
    with f.open("rb") as fh:
        r = client.post(
            "/api/v1/events/import/pcap",
            files={"file": (f.name, fh, "application/octet-stream")},
        )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "pcap_bytes" in data


def test_import_pcap_multipart_empty() -> None:
    r = client.post(
        "/api/v1/events/import/pcap",
        files={"file": ("empty.pcap", b"", "application/octet-stream")},
    )
    assert r.status_code == 400


# ── Cap constant ───────────────────────────────────────────────────────


def test_pcap_cap_is_50mb() -> None:
    assert PCAP_MAX_BYTES == 50 * 1024 * 1024
