"""PCAP ingest glue between the API layer and the pure-Python extractor.

The pcap-flow-extraction skill ships as a standalone script under
``.pi/skills/pcap-flow-extraction/extract_flows.py``. Historically the
ingest code lived inside the API endpoints themselves, which meant
that any change to the flow-schema required editing the FastAPI
handler. This module centralises the parse + ingest logic so the
endpoints only have to call one function.

The functions also enforce the 50 MB cap that
``app.api.v1.PCAP_MAX_BYTES`` advertises, and they return a structured
result so the API can surface the same JSON shape for both the
multipart and the by-path variants.
"""

from __future__ import annotations

import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.services.ingestion import ingest_event, process_events
from app.schemas.event import EventCreate

# Re-use the cap from the API module so a single change updates both
# the request validator and the ingest guard.
from app.api.v1 import PCAP_MAX_BYTES  # noqa: E402

_PI_DIR = Path(__file__).resolve().parents[2] / ".pi"
_EXTRACTOR_PATH = _PI_DIR / "skills" / "pcap-flow-extraction" / "extract_flows.py"


def _load_extractor():
    """Lazy-import the extractor script as a module.

    We can't add ``.pi/...`` to ``sys.path`` permanently because
    ``.pi`` is the operator's private asset directory. A short-lived
    import keeps the dependency local.
    """
    spec = importlib.util.spec_from_file_location("pcap_extractor", _EXTRACTOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load extractor from {_EXTRACTOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _flows_from_bytes(blob: bytes) -> list[dict[str, Any]]:
    """Parse a PCAP/PCAPNG byte stream into flow dicts."""
    if len(blob) > PCAP_MAX_BYTES:
        raise ValueError(
            f"PCAP too large: {len(blob)} bytes (max {PCAP_MAX_BYTES})"
        )
    if len(blob) == 0:
        raise ValueError("empty file")

    extractor = _load_extractor()
    # ``read_pcap`` accepts a Path; write the blob to a temp file
    # because some PCAPNG block-walking code in the script is path-
    # based. We rely on the OS to clean up via tempfile.
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(blob)
        tmp_path = Path(tmp.name)
    try:
        # Sniff the magic number to choose between PCAP and PCAPNG.
        with tmp_path.open("rb") as fh:
            head = fh.read(4)
        if head == b"\x0a\x0d\x0d\x0a":
            packets = extractor.read_pcapng(tmp_path)
        else:
            packets = extractor.read_pcap(tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass

    if not packets:
        return []
    result = extractor.calculate_flows(packets)
    return result.get("flows", [])


def _flows_from_file(src: Path) -> list[dict[str, Any]]:
    """Parse a PCAP/PCAPNG file on disk into flow dicts."""
    size = src.stat().st_size
    if size > PCAP_MAX_BYTES:
        raise ValueError(
            f"PCAP too large: {size} bytes (max {PCAP_MAX_BYTES})"
        )
    if size == 0:
        raise ValueError("empty file")
    return _flows_from_bytes(src.read_bytes())


def _events_from_flows(
    session: Session,
    flows: list[dict[str, Any]],
) -> list:
    """Map extracted flow dicts into EventCreate + persist via ingest_event."""
    import uuid
    events: list = []
    now = datetime.now(timezone.utc)
    for flow in flows:
        # PCAP flows do not carry a stable upstream id (the pcap-flow-
        # extraction skill's ``flow_id`` is per-run, not per-packet).
        # Generate a UUID suffix so two flows from the same PCAP do
        # not collide on the events.external_event_id UNIQUE index.
        flow_id = flow.get("flow_id") or uuid.uuid4().hex[:16]
        events.append(ingest_event(session, EventCreate(
            external_event_id=f"pcap-{flow_id}",
            timestamp=flow.get("start_time") or now,
            sensor="pcap-ingest",
            source_type="pcap",
            source_ip=flow.get("source_ip", ""),
            destination_ip=flow.get("destination_ip", ""),
            source_port=flow.get("source_port", 0),
            destination_port=flow.get("destination_port", 0),
            protocol=flow.get("protocol", "TCP"),
            event_type="pcap",
            action="observed",
            bytes_in=flow.get("backward_bytes", 0),
            bytes_out=flow.get("forward_bytes", 0),
            severity="low",
        )))
    return events


def ingest_pcap_bytes(session: Session, blob: bytes) -> dict[str, Any]:
    """Ingest a PCAP byte stream (used by the multipart endpoint)."""
    try:
        flows = _flows_from_bytes(blob)
    except ValueError as exc:
        return {"status": "error", "detail": str(exc)}
    events = _events_from_flows(session, flows)
    incidents = process_events(session, events)
    return {
        "ingested": len(events),
        "flows": len(flows),
        "incidents": [incident.public_id for incident in incidents],
        "pcap_bytes": len(blob),
    }


def ingest_pcap_file(session: Session, src: Path) -> dict[str, Any]:
    """Ingest a PCAP file on disk (used by the by-path endpoints)."""
    try:
        flows = _flows_from_file(src)
    except ValueError as exc:
        return {"status": "error", "detail": str(exc)}
    events = _events_from_flows(session, flows)
    incidents = process_events(session, events)
    return {
        "ingested": len(events),
        "flows": len(flows),
        "incidents": [incident.public_id for incident in incidents],
        "pcap_bytes": src.stat().st_size,
        "source": str(src),
    }
