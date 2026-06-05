# Ket qua Incident Response

- Alert ID: ALERT-2026-09-001
- Thoi gian chay: 2026-06-05T16:08:20+00:00
- Phan loai: Web Attack
- Muc do: high
- Do tin cay: 0.94

## MITRE ATT&CK Mapping
- T1190 - Exploit Public-Facing Application (Initial Access), score=0.68
- T1040 - Network Sniffing/Traffic Observation (Collection), score=0.4
- T1040 - Network Sniffing/Traffic Observation (Collection), score=0.4
- T1040 - Network Sniffing/Traffic Observation (Collection), score=0.4
- T1040 - Network Sniffing/Traffic Observation (Collection), score=0.4
- T1190 - Exploit Public-Facing Application (Initial Access), score=0.35
- T1046 - Network Service Discovery (Discovery), score=0.18
- T1041 - Exfiltration Over C2 Channel (Exfiltration), score=0.12

## Containment Steps
- simulate_notify_admin
- simulate_block_ip
- simulate_quarantine_host

## Evidence
- Port Scan / medium: Scanned 11 distinct ports in 60s window; Ports: [21, 22, 23, 25, 53, 80, 110, 139, 445, 1433, 3389]; Total events in window: 12
- Web Attack / medium: Suspicious URL: /login.php?id=1%27%20or%201=1; Matched patterns: ['SQL Injection (UNION/select)']; User-Agent: curl/8.0
- Web Attack / high: Suspicious URL: /download?file=../../../../etc/passwd; Matched patterns: ['Path Traversal', 'Sensitive file access']; User-Agent: curl/8.0
- Data Exfiltration / high: Total outbound: 82,400,000 bytes (78.6 MB) in 300s; Number of connections: 1; Source IPs involved: 1
- Policy Violation / medium: Access to blocked port 139/TCP; Blocked ports policy: [135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200]...
- Policy Violation / medium: Access to blocked port 445/TCP; Blocked ports policy: [135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200]...
- Policy Violation / medium: Access to blocked port 1433/TCP; Blocked ports policy: [135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200]...
- Policy Violation / medium: Access to blocked port 3389/TCP; Blocked ports policy: [135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200]...
