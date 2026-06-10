# Pi Skills Registry

This document lists the persistent functional capabilities (Skills) implemented in N.I.R.O. Each skill is located in `.pi/skills/<skill-name>/` and contains a `SKILL.md` manifest along with an implementation script.

---

## 1. Core Skills List

### 1.1 Event Ingestion (`event-ingestion`)
- **Purpose**: Normalizes raw network events, validates syntax, and writes output to the SQLModel database.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/event-ingestion/SKILL.md)
- **Script**: `ingest_events.py`

### 1.2 Suricata Analysis (`suricata-analysis`)
- **Purpose**: Parses Suricata EVE JSON alerts (flows, dns, http, tls, anomalies) and maps them to standard schema formats.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/suricata-analysis/SKILL.md)
- **Script**: `parse_eve.py`

### 1.3 Zeek Analysis (`zeek-analysis`)
- **Purpose**: Decodes Zeek JSON logs (conn, dns, http, ssl) for network metadata extraction.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/zeek-analysis/SKILL.md)
- **Script**: `parse_zeek.py`

### 1.4 PCAP Flow Extraction (`pcap-flow-extraction`)
- **Purpose**: Computes bidirectional flow features (bytes, packets, flags, packet length mean/std, inter-arrival time) from packet capture (PCAP) streams.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/pcap-flow-extraction/SKILL.md)
- **Script**: `extract_flows.py`

### 1.5 Auth Investigation (`auth-investigation`)
- **Purpose**: Analyzes authentication histories, logon failure frequencies, brute-force indicators, and targeted user lists.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/auth-investigation/SKILL.md)
- **Script**: `analyse_auth.py`

### 1.6 DNS Investigation (`dns-investigation`)
- **Purpose**: Inspects DNS queries for dynamic domain names, high query volumes, or potential DGA (Domain Generation Algorithm) indicators.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/dns-investigation/SKILL.md)
- **Script**: `analyse_dns.py`

### 1.7 Threat Intelligence (`threat-intelligence`)
- **Purpose**: Queries reputational data feeds for external IP addresses, mapping them to ASN, geolocation, or proxy/Tor categories.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/threat-intelligence/SKILL.md)
- **Script**: `threat_intel.py`

### 1.8 MITRE Mapping (`mitre-mapping`)
- **Purpose**: Looks up Technique IDs and Tactics mapping to specific security findings.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/mitre-mapping/SKILL.md)
- **Script**: `mitre_lookup.py`

### 1.9 Incident Explanation (`incident-explanation`)
- **Purpose**: Constructs an evidence context model, sorting facts from inferences to present to the operator.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/incident-explanation/SKILL.md)
- **Script**: `build_evidence_context.py`

### 1.10 Response Planning (`response-planning`)
- **Purpose**: Formulates containment actions and checks them against the active security policies.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/response-planning/SKILL.md)
- **Script**: `propose_actions.py`

### 1.11 Report Generation (`report-generation`)
- **Purpose**: Generates consolidated Markdown, JSON, and PDF reports summarizing the incident lifecycle.
- **Manifest**: [SKILL.md](file:///d:/New%20folder/Network-Incident-Response-Orchestrator/.pi/skills/report-generation/SKILL.md)
- **Script**: `generate_report.py`
