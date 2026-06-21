"""Async TCP and UDP collectors for ingesting network event telemetry."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from sqlmodel import Session

from app.db.session import engine
from app.schemas.event import EventCreate
from app.services.ingestion import ingest_event, process_events

logger = logging.getLogger("niro.collectors")


class NetworkListeners:
    """Async socket collectors for receiving network events."""

    def __init__(self, host: str = "127.0.0.1", tcp_port: int = 9001, udp_port: int = 9002) -> None:
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self._tcp_server: asyncio.Server | None = None
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._shutdown = False

    async def start(self) -> None:
        """Start both TCP and UDP listeners."""
        # TCP server
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp_connection, self.host, self.tcp_port
        )
        logger.info("TCP collector listening on %s:%d", self.host, self.tcp_port)

        # UDP server
        loop = asyncio.get_running_loop()
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(self),
            local_addr=(self.host, self.udp_port)
        )
        logger.info("UDP syslog collector listening on %s:%d", self.host, self.udp_port)

    async def stop(self) -> None:
        """Gracefully stop listeners."""
        self._shutdown = True
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            logger.info("TCP collector shut down")
        if self._udp_transport:
            self._udp_transport.close()
            logger.info("UDP collector shut down")

    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_address = writer.get_extra_info("peername")
        logger.debug("New TCP collector connection from %s", client_address)
        try:
            while not self._shutdown:
                # Read newline delimited JSON
                line = await reader.readline()
                if not line:
                    break
                
                try:
                    payload = json.loads(line.decode("utf-8").strip())
                    self.ingest_raw_payload(payload)
                except Exception as e:
                    logger.error("TCP parse error: %s", e)
        except Exception as e:
            logger.error("TCP connection error from %s: %s", client_address, e)
        finally:
            writer.close()
            await writer.wait_closed()

    def ingest_raw_payload(self, payload: dict[str, Any]) -> None:
        """Parse and ingest a raw received event."""
        try:
            event_data = EventCreate(
                external_event_id=payload.get("event_id") or payload.get("flow_id") or payload.get("external_event_id"),
                timestamp=payload.get("timestamp"),
                sensor=payload.get("sensor") or "socket_collector",
                source_type=payload.get("source_type") or "syslog",
                source_ip=payload.get("source_ip") or payload.get("src_ip", "0.0.0.0"),
                destination_ip=payload.get("destination_ip") or payload.get("dst_ip", "0.0.0.0"),
                source_port=payload.get("source_port") or payload.get("src_port"),
                destination_port=payload.get("destination_port") or payload.get("dest_port") or payload.get("dst_port"),
                protocol=payload.get("protocol") or payload.get("proto", "TCP"),
                event_type=payload.get("event_type") or "syslog",
                action=payload.get("action"),
                username=payload.get("username"),
                url=payload.get("url"),
                domain=payload.get("domain"),
                flow_id=payload.get("flow_id"),
                severity=payload.get("severity") or "medium",
                user_agent=payload.get("user_agent"),
                bytes_in=payload.get("bytes_in", 0),
                bytes_out=payload.get("bytes_out", 0),
                raw=payload,
            )
            with Session(engine) as session:
                event = ingest_event(session, event_data)
                process_events(session, [event])
                logger.info("Ingested event ID %s via collector", event.id)
        except Exception as e:
            logger.error("Failed to ingest event from collector: %s", e)


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Protocol for reading UDP syslog datagrams."""

    def __init__(self, parent: NetworkListeners) -> None:
        self.parent = parent
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            # Parse syslog message (which might be JSON, or CEF, or RFC5424)
            msg = data.decode("utf-8").strip()
            # Simple check if it's JSON
            if msg.startswith("{"):
                payload = json.loads(msg)
            else:
                # Basic parsing for plain syslog text
                payload = {"message": msg, "source_ip": addr[0], "event_type": "syslog"}
            self.parent.ingest_raw_payload(payload)
        except Exception as e:
            logger.error("UDP datagram parse error: %s", e)
