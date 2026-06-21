---
name: pcap-flow-extraction
description: >
  Extract bidirectional five-tuple flows from PCAP files and compute flow features for ML anomaly detection.
  Supports offline analysis without root privileges.
triggers:
  - pcap
  - packet capture
  - flow extraction
  - network flows
  - pcap analysis
inputs:
  - pcap_file: str (path to PCAP/PCAPNG file)
  - max_packets: int (optional, limit for testing)
outputs:
  - flows: list[dict]
  - features: list[dict]
  - statistics: dict
safety: read-only
---

# PCAP Flow Extraction Skill

## Purpose
Convert raw packet captures into bidirectional flow records with computed features for detection and ML pipelines.

## When to Use
- PCAP files are uploaded for offline analysis
- Flow-level features needed for ML anomaly detection
- Bidirectional traffic analysis required
- Network protocol distribution needed

## Inputs
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| pcap_file | str | Yes | Path to PCAP or PCAPNG file |
| max_packets | int | No | Maximum packets to process (for testing) |

## Environment
- Python 3.11+
- `scapy` library (optional, gracefully handled if unavailable)
- `dpkt` library as fallback

## Procedure
1. Open PCAP file using scapy or dpkt
2. Iterate packets, extract five-tuple: src_ip, dst_ip, src_port, dst_port, protocol
3. Canonicalize flow key (sort endpoints for bidirectional grouping)
4. Accumulate per-flow statistics:
   - Packet counts, byte counts (forward/backward)
   - Timestamps (first, last, duration)
   - TCP flags (SYN, ACK, FIN, RST, PSH)
   - Inter-arrival times
   - Packet length statistics
5. Compute derived features: bytes/sec, pkts/sec, ratios, IAT statistics
6. Handle edge cases: empty flows, zero duration, NaN, infinity
7. Return flows with features and summary statistics

## Commands
```bash
python .pi/skills/pcap-flow-extraction/extract_flows.py --file capture.pcap
python .pi/skills/pcap-flow-extraction/extract_flows.py --file capture.pcapng --max-packets 10000
```

## Output Schema
```json
{
  "flows": [
    {
      "flow_id": "flw-abc123",
      "source_ip": "203.0.113.77",
      "destination_ip": "10.10.20.15",
      "source_port": 45210,
      "destination_port": 443,
      "protocol": "TCP",
      "start_time": "2026-06-10T15:20:00.123Z",
      "end_time": "2026-06-10T15:20:05.456Z",
      "duration": 5.333,
      "total_packets": 25,
      "forward_packets": 10,
      "backward_packets": 15,
      "total_bytes": 3072,
      "forward_bytes": 1024,
      "backward_bytes": 2048,
      "bytes_per_second": 576.0,
      "packets_per_second": 4.69,
      "fwd_pkt_len_mean": 102.4,
      "fwd_pkt_len_std": 15.2,
      "bwd_pkt_len_mean": 136.5,
      "bwd_pkt_len_std": 22.1,
      "flow_iat_mean": 0.533,
      "flow_iat_std": 0.12,
      "fwd_iat_mean": 0.6,
      "fwd_iat_std": 0.15,
      "bwd_iat_mean": 0.4,
      "bwd_iat_std": 0.1,
      "syn_count": 1,
      "ack_count": 20,
      "fin_count": 1,
      "rst_count": 0,
      "psh_count": 5,
      "fwd_bwd_byte_ratio": 0.5,
      "active_time": 5.333,
      "idle_time": 0.0
    }
  ],
  "statistics": {
    "total_packets": 10000,
    "total_flows": 150,
    "protocols": {"TCP": 120, "UDP": 25, "ICMP": 5},
    "unique_src_ips": 45,
    "unique_dst_ips": 30
  }
}
```

## Interpretation Rules
- Flow key canonicalized: (min(src,dst), max(src,dst), ports, proto)
- Forward = first packet direction, backward = reverse
- Zero duration flows get duration = 1 microsecond for rate calculations
- NaN/infinity replaced with 0 or capped at max observed
- Truncated packets noted in flow metadata

## Error Handling
- Unsupported protocols (non-IP) skipped with count
- Corrupted packets skipped with warning
- Missing scapy/dpkt returns error with install instructions
- Large files processed in chunks

## Safety Constraints
- Read-only: no network capture, no file modification
- No root required (offline file only)
- Memory bounded by chunked processing
- File access limited to provided path

## Verification Command
```bash
python -m pytest tests/unit/test_pcap_flow_extraction.py -v
```