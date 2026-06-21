"""Event ingestion, detection, and incident persistence services."""

from __future__ import annotations

from datetime import datetime, timedelta
import json
from typing import Any

from sqlmodel import Session, select

from app.core.config import settings
from app.core.json import jsonable
from app.detection.anomaly_detector import anomaly_detector
from app.detection.rule_engine import analyze_events
from app.models.event import Event
from app.models.incident import AuditEntry, Finding, Incident
from app.schemas.event import EventCreate

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
ACTIVE_INCIDENT_STATUSES = {"new", "triaging", "investigating", "awaiting_approval", "containing", "monitoring"}


def ingest_event(session: Session, payload: EventCreate) -> Event:
    """Persist one normalized event idempotently when external_event_id is present."""
    if payload.external_event_id:
        existing = session.exec(
            select(Event).where(Event.external_event_id == payload.external_event_id)
        ).first()
        if existing:
            return existing
    event = Event(
        external_event_id=payload.external_event_id,
        timestamp=payload.timestamp or datetime.utcnow(),
        sensor=payload.sensor,
        source_type=payload.source_type,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        source_port=payload.source_port,
        destination_port=payload.destination_port,
        protocol=payload.protocol,
        event_type=payload.event_type,
        action=payload.action,
        username=payload.username,
        url=payload.url,
        domain=payload.domain,
        flow_id=payload.flow_id,
        severity=payload.severity,
        user_agent=payload.user_agent,
        bytes_in=payload.bytes_in,
        bytes_out=payload.bytes_out,
        normalized=payload.model_dump(exclude_none=True, mode="json"),
        raw=payload.raw,
    )
    session.add(event)
    session.commit()
    session.refresh(event)
    audit(session, "system", "event.ingest", "event", str(event.id), after=event.normalized)
    return event


def process_events(session: Session, events: list[Event]) -> list[Incident]:
    """Run rule detection on events and persist findings/incidents."""
    event_dicts = [_event_to_dict(event) for event in events]
    findings = analyze_events(sorted(event_dicts, key=lambda item: item["timestamp"]))
    if settings.ml_anomaly_enabled:
        findings.extend(anomaly_detector.find_anomalies(event_dicts, settings.ml_anomaly_threshold))
    incidents: list[Incident] = []
    for finding_data in findings:
        finding = _persist_finding(session, finding_data, events)
        incident = correlate_finding(session, finding, finding_data)
        incidents.append(incident)
        try:
            from app.orchestration.engine import orchestrator_engine
            if incident.id is not None:
                orchestrator_engine.submit_incident(incident.id)
        except Exception:
            pass
    return incidents



def correlate_finding(session: Session, finding: Finding, finding_data: dict[str, Any]) -> Incident:
    """Create or update an open incident for a finding."""
    key_source = finding.source_ip or ""
    key_dest = finding.destination_ip or ""
    cutoff = datetime.utcnow() - timedelta(hours=settings.correlation_window_hours)
    existing = session.exec(
        select(Incident).where(
            Incident.status.in_(ACTIVE_INCIDENT_STATUSES),
            Incident.incident_type == finding.incident_type,
            Incident.source_ip == key_source,
            Incident.destination_ip == key_dest,
            Incident.updated_at >= cutoff,
        )
    ).first()
    evidence = [{"finding_id": finding.id, "summary": finding.evidence_summary}]
    if existing:
        before = existing.model_dump()
        existing.confidence = max(existing.confidence, finding.confidence)
        if SEVERITY_WEIGHT.get(finding.severity, 0) > SEVERITY_WEIGHT.get(existing.severity, 0):
            existing.severity = finding.severity
        existing.last_seen = finding.last_seen or finding.first_seen
        existing.evidence = _dedupe_evidence((existing.evidence or []) + evidence)
        existing.updated_at = datetime.utcnow()
        existing.correlation_reason = (
            f"matched type, source, destination, active status, and {settings.correlation_window_hours}h window"
        )
        session.add(existing)
        session.commit()
        session.refresh(existing)
        finding.incident_id = existing.id
        session.add(finding)
        session.commit()
        audit(session, "system", "incident.update", "incident", existing.public_id, before, existing.model_dump())
        return existing

    public_id = next_incident_id(session)
    incident = Incident(
        public_id=public_id,
        title=f"{finding.incident_type} from {key_source or 'unknown'}",
        incident_type=finding.incident_type,
        severity=finding.severity,
        confidence=finding.confidence,
        source_ip=key_source,
        destination_ip=key_dest,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen or finding.first_seen,
        evidence=evidence,
        summary=finding.evidence_summary,
        recommended_actions=finding_data.get("recommended_actions", []),
        correlation_reason="new correlation key",
    )
    session.add(incident)
    session.commit()
    session.refresh(incident)
    finding.incident_id = incident.id
    session.add(finding)
    session.commit()
    audit(session, "system", "incident.create", "incident", incident.public_id, after=incident.model_dump())
    return incident


def next_incident_id(session: Session) -> str:
    count = len(session.exec(select(Incident.id)).all()) + 1
    return f"INC-{count:06d}"


def audit(
    session: Session,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditEntry(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            before_state=jsonable(before),
            after_state=jsonable(after),
        )
    )
    session.commit()





def _dedupe_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[-settings.correlation_max_evidence_items :]


def _persist_finding(session: Session, data: dict[str, Any], events: list[Event]) -> Finding:
    related_ids = [
        event.id
        for event in events
        if event.id is not None
        and (event.source_ip == data.get("source_ip") or event.destination_ip == data.get("destination_ip"))
    ]
    timestamps = [event.timestamp for event in events if event.id in related_ids]
    finding = Finding(
        detector_id=f"rule.{data['incident_type'].lower().replace(' ', '_').replace('/', '_')}",
        incident_type=data["incident_type"],
        severity=data["severity"],
        confidence=float(data["confidence"]),
        source_ip=data.get("source_ip") or "",
        destination_ip=data.get("destination_ip") or "",
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
        evidence_summary="; ".join(data.get("evidence", [])),
        related_event_ids=related_ids,
        ml_score=data.get("ml_score"),
        recommended_playbooks=data.get("recommended_actions", []),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def _event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "event_type": event.event_type,
        "action": event.action,
        "username": event.username,
        "url": event.url,
        "user_agent": event.user_agent,
        "bytes_in": event.bytes_in,
        "bytes_out": event.bytes_out,
        "domain": event.domain,
        "flow_id": event.flow_id,
    }
