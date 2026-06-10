# Response Safety & Permission Gates

This document describes the safety controls, risk policies, and adapters that govern containment actions in N.I.R.O.

---

## 1. Risk Classifications

Actions proposed by the agent are categorized by risk level, which determines whether they can execute automatically or require operator approval:

| Action Category | Target / Description | Risk Level | Policy Decision |
|---|---|---|---|
| **Read-Only / Lookup** | Querying logs, DNS lists, reputational databases | Low | Automatic |
| **Notification** | Webhooks, Slack, admin alerts | Low | Automatic |
| **Temporary IP Block** | Blocking an external attacker IP at the firewall | Medium | Requires Human Approval |
| **Host Quarantine** | Isolating an infected internal workstation | High | Requires Human Approval |
| **Disable User** | Disabling a compromised Active Directory account | High | Requires Human Approval |
| **Permanent IP Block** | Permanently blocking a subnet without time limits | Critical | Denied by default |
| **Destructive / Attack** | Exploit payloads, deleting logs, offensive scans | Critical | Denied |

---

## 2. Security Permission Gate

The Permission Gate (implemented as a TypeScript Pi Extension and a Python service check) intercepts every action before execution:
1. **Command Review**: Inspects the command line and targets.
2. **Bash Interception**: Rejects arbitrary bash shell execution or commands containing shell syntax metacharacters.
3. **Approval Queue**: Places all actions requiring approval into the `awaiting_approval` queue. Execution is blocked until an operator triggers `POST /actions/{id}/approve`.

---

## 3. Protected Address Policy

The firewall adapter (`nftables`) and simulated adapters enforce strict destination/target verification to prevent self-denial of service. Blocking requests targetting the following objects are **always blocked**:
- **Loopback**: `127.0.0.0/8`, `::1`
- **Broadcast / Multicast**: `255.255.255.255`, `224.0.0.0/4`
- **Application Management IP**: Localhost or IP running the N.I.R.O backend/frontend.
- **Default Gateways**: Local router IP address.
- **Allowlisted Assets**: Assets marked as "critical" in the inventory file.

---

## 4. Rollback and Expiration Timers

- **Reversibility**: Every action must define a rollback procedure (e.g. `simulate_unblock_ip`). Rollback instructions and initial states are persisted in the database.
- **Expiration Timers**: IP blocks and isolations are configured as temporary actions with a defined duration (e.g. 3600 seconds). After the duration expires, the background worker automatically triggers the rollback procedure to restore connection states.
- **Manual Rollback**: Operators can select any active action on the dashboard and click `[ ROLLBACK ]` to immediately undo changes.
