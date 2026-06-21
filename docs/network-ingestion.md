# Network Ingestion & Log Collection

This document describes how the N.I.R.O. backend ingests, normalizes, and parses network security telemetry.

---

## 1. Real-Time Socket Collectors

The network listeners are defined in `app/collectors/listeners.py` and run asynchronously within the FastAPI lifespan context. They are disabled by default for safety but can be configured in settings.

### 1.1 Async TCP Event Listener
- **Implementation**: Utilizes `asyncio.start_server` to establish a non-blocking TCP socket.
- **Protocol**: Listens on port `9001` (by default) for newline-delimited JSON log strings.
- **Robustness**: Enforces connection timeouts, max message size caps (10KB), and error isolation per client connection to prevent crashes.

### 1.2 Async UDP Syslog Listener
- **Implementation**: Inherits from `asyncio.DatagramProtocol` to ingest datagrams.
- **Protocol**: Listens on port `9002` (by default) for RFC-5424 syslog packets.
- **Robustness**: Extracts source addresses, handles packet truncation safely, and parses JSON payloads without blocking.

---

## 2. Ingestion Formats

### 2.1 Suricata EVE JSON
Parsed in `app/collectors/suricata.py`. Supports extracting alerts, flows, dns lookups, http sessions, tls handshakes, and anomalies. Maps Suricata's `flow_id` to correlate related alerts.

### 2.2 Zeek JSON logs
Parsed in `app/collectors/zeek.py`. Decodes standard Zeek formats:
- `conn.log` -> Connection statistics (bytes, packet counts, flags).
- `dns.log` -> Queries, answers, and record classes.
- `http.log` -> URIs, response codes, and User-Agents.
- `ssl.log` -> Cipher suites, subject names, and validation statuses.

### 2.3 PCAP Upload & Flow Extraction
Supports uploading `.pcap` / `.pcapng` files. Uses offline pcap parsing to group packets into conversation flows based on a 5-tuple key:
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol (TCP/UDP/ICMP)
Calculates duration, total packet/byte volumes, SYN/ACK flags, inter-arrival times (IAT), and forward-to-backward ratios. Run entirely in user space without requiring root privileges.
