"""Async multi-phase queue-based orchestration engine."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from sqlmodel import Session

from app.db.session import engine
from app.services.agent_runs import run_agent_for_incident
from app.core.paths import PI_DIR

logger = logging.getLogger("niro.orchestration")

# Configuration limits
MAX_CONCURRENT_INCIDENTS = 5
MAX_CONCURRENT_TOOLS = 10
PHASE_TIMEOUT_SECONDS = 300
TOOL_TIMEOUT_SECONDS = 30
QUEUE_MAX_SIZE = 1000


class OrchestratorEngine:
    """Async queue engine managing concurrent phase-based incident triage."""

    def __init__(self) -> None:
        self.ingestion_queue: asyncio.Queue[int] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
        self.evidence_queue: asyncio.Queue[int] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
        self.detection_queue: asyncio.Queue[int] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
        self.triage_queue: asyncio.Queue[int] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
        self.response_queue: asyncio.Queue[int] = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)

        self._active_incidents: dict[int, dict[str, Any]] = {}
        self._workers: list[asyncio.Task] = []
        self._incident_semaphore = asyncio.Semaphore(MAX_CONCURRENT_INCIDENTS)
        self._running = False
        self._event_listeners: list[asyncio.Queue[dict[str, Any]]] = []

    def start(self) -> None:
        """Start background queue workers."""
        if self._running:
            return
        self._running = True
        loop = asyncio.get_running_loop()
        self._workers = [
            loop.create_task(self._wrap_worker(self._ingestion_worker, "Intake")),
            loop.create_task(self._wrap_worker(self._evidence_worker, "Evidence")),
            loop.create_task(self._wrap_worker(self._detection_worker, "Detection")),
            loop.create_task(self._wrap_worker(self._triage_worker, "Triage")),
            loop.create_task(self._wrap_worker(self._response_worker, "Response")),
        ]
        logger.info("Orchestration engine workers started")

    async def stop(self) -> None:
        """Stop all background workers."""
        self._running = False
        for t in self._workers:
            t.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("Orchestration engine workers stopped")

    def submit_incident(self, incident_id: int) -> None:
        """Submit an incident to the intake (ingestion) queue."""
        try:
            self.ingestion_queue.put_nowait(incident_id)
            self._active_incidents[incident_id] = {
                "incident_id": incident_id,
                "current_phase": "Intake",
                "status": "waiting",
                "started_at": datetime.utcnow().isoformat(),
                "duration": 0.0
            }
            self._broadcast({"type": "incident_queued", "incident_id": incident_id, "queue": "ingestion"})
        except asyncio.QueueFull:
            logger.error("Ingestion queue full, dropped incident %d", incident_id)

    def register_listener(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._event_listeners.append(q)

    def unregister_listener(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self._event_listeners:
            self._event_listeners.remove(q)

    def get_status(self) -> dict[str, Any]:
        """Return metrics on queue depth and active incident states."""
        return {
            "queues": {
                "ingestion": self.ingestion_queue.qsize(),
                "evidence": self.evidence_queue.qsize(),
                "detection": self.detection_queue.qsize(),
                "triage": self.triage_queue.qsize(),
                "response": self.response_queue.qsize(),
            },
            "active_incidents": list(self._active_incidents.values()),
            "concurrency_limit": MAX_CONCURRENT_INCIDENTS,
        }

    def _broadcast(self, event: dict[str, Any]) -> None:
        for q in self._event_listeners:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def _wrap_worker(self, worker_func: Any, name: str) -> None:
        while self._running:
            try:
                await worker_func()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("%s worker error: %s", name, e)
                await asyncio.sleep(2)

    async def _ingestion_worker(self) -> None:
        incident_id = await self.ingestion_queue.get()
        async with self._incident_semaphore:
            self._update_incident(incident_id, "Intake", "running")
            await asyncio.sleep(1.0)  # Simulate normalization/parsing overhead
            self._update_incident(incident_id, "Intake", "completed")
            await self.evidence_queue.put(incident_id)
        self.ingestion_queue.task_done()

    async def _evidence_worker(self) -> None:
        incident_id = await self.evidence_queue.get()
        async with self._incident_semaphore:
            self._update_incident(incident_id, "Evidence Acquisition", "running")
            try:
                # Call agent evidence skill via asyncio.wait_for
                await asyncio.wait_for(self._run_phase_agent(incident_id, "Collect evidence"), timeout=TOOL_TIMEOUT_SECONDS)
                self._update_incident(incident_id, "Evidence Acquisition", "completed")
                await self.detection_queue.put(incident_id)
            except asyncio.TimeoutError:
                logger.error("Incident %d evidence timeout", incident_id)
                self._update_incident(incident_id, "Evidence Acquisition", "timeout")
        self.evidence_queue.task_done()

    async def _detection_worker(self) -> None:
        incident_id = await self.detection_queue.get()
        async with self._incident_semaphore:
            self._update_incident(incident_id, "Detection/ML Anomaly", "running")
            try:
                await asyncio.wait_for(self._run_phase_agent(incident_id, "Analyze alerts and detect anomalies"), timeout=TOOL_TIMEOUT_SECONDS)
                self._update_incident(incident_id, "Detection/ML Anomaly", "completed")
                await self.triage_queue.put(incident_id)
            except asyncio.TimeoutError:
                logger.error("Incident %d detection timeout", incident_id)
                self._update_incident(incident_id, "Detection/ML Anomaly", "timeout")
        self.detection_queue.task_done()

    async def _triage_worker(self) -> None:
        incident_id = await self.triage_queue.get()
        async with self._incident_semaphore:
            self._update_incident(incident_id, "Triage/MITRE Mapping", "running")
            try:
                await asyncio.wait_for(self._run_phase_agent(incident_id, "Map to MITRE tactics"), timeout=TOOL_TIMEOUT_SECONDS)
                self._update_incident(incident_id, "Triage/MITRE Mapping", "completed")
                await self.response_queue.put(incident_id)
            except asyncio.TimeoutError:
                logger.error("Incident %d triage timeout", incident_id)
                self._update_incident(incident_id, "Triage/MITRE Mapping", "timeout")
        self.triage_queue.task_done()

    async def _response_worker(self) -> None:
        incident_id = await self.response_queue.get()
        async with self._incident_semaphore:
            self._update_incident(incident_id, "Response Planning", "running")
            try:
                await asyncio.wait_for(self._run_phase_agent(incident_id, "Propose response actions"), timeout=TOOL_TIMEOUT_SECONDS)
                self._update_incident(incident_id, "Response Planning", "completed")
                # Remove from active list as pipeline completes
                if incident_id in self._active_incidents:
                    del self._active_incidents[incident_id]
                self._broadcast({"type": "pipeline_completed", "incident_id": incident_id})
            except asyncio.TimeoutError:
                logger.error("Incident %d response timeout", incident_id)
                self._update_incident(incident_id, "Response Planning", "timeout")
        self.response_queue.task_done()

    def _update_incident(self, incident_id: int, phase: str, status: str) -> None:
        if incident_id in self._active_incidents:
            self._active_incidents[incident_id]["current_phase"] = phase
            self._active_incidents[incident_id]["status"] = status
            
            # Calculate duration
            started = datetime.fromisoformat(self._active_incidents[incident_id]["started_at"])
            delta = (datetime.utcnow() - started).total_seconds()
            self._active_incidents[incident_id]["duration"] = round(delta, 1)

        self._broadcast({
            "type": "phase_update",
            "incident_id": incident_id,
            "phase": phase,
            "status": status
        })

    async def _run_phase_agent(self, incident_id: int, task: str) -> None:
        """Run the actual Pi agent loop in a separate thread to keep engine async."""
        loop = asyncio.get_running_loop()
        
        def run() -> None:
            with Session(engine) as session:
                run_agent_for_incident(session, incident_id, task, PI_DIR)
                
        await loop.run_in_executor(None, run)


# Global Engine Singleton
orchestrator_engine = OrchestratorEngine()
