# Demo Scenarios Guide

This document describes how to execute and verify the synthetic demo scenarios provided in the N.I.R.O. repository.

---

## 1. Scenario Catalog

### Scenario A — SSH Brute Force
- **Description**: Simulates 6 failed login attempts targeting an internal system.
- **Trigger Command**:
  ```bash
  python scripts/load_demo.py --scenario ssh-bruteforce
  ```
- **Expectation**: An incident `INC-XXXXXX` of type `Brute Force` will be created with severity `high`. Running the agent will propose a simulated firewall block and target user account disable.

### Scenario B — Port Scan
- **Description**: Simulates 12 distinct destination port connections from a single IP.
- **Trigger Command**:
  ```bash
  python scripts/load_demo.py --scenario port-scan
  ```
- **Expectation**: An incident of type `Port Scan` is created with severity `high`/`medium`. The agent proposes adding the source IP to a watchlist and blocking it at the perimeter.

### Scenario C — C2 Beaconing
- **Description**: Simulates 7 periodic connections spaced exactly 15 seconds apart targeting a public IP address.
- **Trigger Command**:
  ```bash
  python scripts/load_demo.py --scenario c2-beaconing
  ```
- **Expectation**: An incident of type `C2 Beaconing` is created. The periodicity check passes (jitter < 10s) and confidence is rated near `1.0`. Proposes host isolation and DNS reputation checks.

### Scenario D — Data Exfiltration
- **Description**: Simulates a single connection transferring over 50MB of data to a public IP.
- **Trigger Command**:
  ```bash
  python scripts/load_demo.py --scenario data-exfil
  ```
- **Expectation**: An incident of type `Data Exfiltration` is created. Proposes host isolation and staging directory investigations.

### Scenario E — False Positive
- **Description**: Simulates scan events from an approved scanner IP (`10.0.0.99`).
- **Trigger Command**:
  ```bash
  python scripts/load_demo.py --scenario false-positive
  ```
- **Expectation**: Ingests the events, but 0 incidents are created because the source IP matches the approved scanner filter in policies, demonstrating policy-driven suppression.

---

## 2. End-to-End Execution Flow

To verify the complete lifecycle of an incident in a CLI environment:

1. **Load the Scenario**:
   ```bash
   python scripts/load_demo.py --scenario ssh-bruteforce
   ```
   *Record the created incident number (e.g. `INC-000112`).*

2. **Execute Agent Reasoning**:
   ```bash
   python scripts/run_incident.py --latest
   ```
   *This loads the incident details, matches the triage skill, executes tool calls, runs LLM analysis, maps to MITRE, and proposes actions.*

3. **Verify Status**:
   - Inspect the database contents using the Web UI console at `/operations` or `/incidents`.
   - Verify that actions proposed appear in `/approvals` under the `awaiting_approval` state.
