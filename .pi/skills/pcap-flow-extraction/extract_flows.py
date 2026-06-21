#!/usr/bin/env python3
"""Pure Python PCAP and PCAPNG flow extractor and feature calculator."""

from __future__ import annotations

import argparse
import json
import struct
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def ip_to_str(ip_bytes: bytes) -> str:
    return ".".join(str(b) for b in ip_bytes)


class PacketInfo:
    def __init__(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        length: int,
        flags: int = 0,
    ) -> None:
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.flags = flags


def parse_ipv4_packet(packet_data: bytes, ts: float) -> PacketInfo | None:
    # Minimal Ethernet parsing (offset 14)
    if len(packet_data) < 34:
        return None
    eth_type = struct.unpack("!H", packet_data[12:14])[0]
    
    ip_offset = 14
    if eth_type == 0x8100:  # VLAN
        eth_type = struct.unpack("!H", packet_data[16:18])[0]
        ip_offset = 18

    if eth_type != 0x0800:  # Not IPv4
        return None

    if len(packet_data) < ip_offset + 20:
        return None

    ihl = (packet_data[ip_offset] & 0x0F) * 4
    proto = packet_data[ip_offset + 9]
    src_ip = ip_to_str(packet_data[ip_offset + 12: ip_offset + 16])
    dst_ip = ip_to_str(packet_data[ip_offset + 16: ip_offset + 20])

    l4_offset = ip_offset + ihl
    if proto == 6:  # TCP
        if len(packet_data) < l4_offset + 20:
            return None
        src_port, dst_port = struct.unpack("!HH", packet_data[l4_offset: l4_offset + 4])
        flags = packet_data[l4_offset + 13]
        return PacketInfo(ts, src_ip, dst_ip, src_port, dst_port, "TCP", len(packet_data), flags)
    elif proto == 17:  # UDP
        if len(packet_data) < l4_offset + 8:
            return None
        src_port, dst_port = struct.unpack("!HH", packet_data[l4_offset: l4_offset + 4])
        return PacketInfo(ts, src_ip, dst_ip, src_port, dst_port, "UDP", len(packet_data))
    elif proto == 1:  # ICMP
        return PacketInfo(ts, src_ip, dst_ip, 0, 0, "ICMP", len(packet_data))

    return None


def read_pcap(path: Path, max_packets: int | None = None) -> list[PacketInfo]:
    packets = []
    with path.open("rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return []
        
        magic = struct.unpack("<I", global_header[0:4])[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
            nano = False
        elif magic == 0xD4C3B2A1:
            endian = ">"
            nano = False
        elif magic == 0xA1B23C4D:
            endian = "<"
            nano = True
        elif magic == 0x4D3CB2A1:
            endian = ">"
            nano = True
        else:
            # Try parsing as PCAPNG
            return read_pcapng(path, max_packets)

        while True:
            if max_packets is not None and len(packets) >= max_packets:
                break
            header = f.read(16)
            if len(header) < 16:
                break
            ts_sec, ts_usec, caplen, origlen = struct.unpack(f"{endian}IIII", header)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            
            ts = ts_sec + (ts_usec / (1e9 if nano else 1e6))
            pkt = parse_ipv4_packet(data, ts)
            if pkt:
                packets.append(pkt)
    return packets


def read_pcapng(path: Path, max_packets: int | None = None) -> list[PacketInfo]:
    packets = []
    with path.open("rb") as f:
        # Loop through blocks
        endian = "<"
        while True:
            if max_packets is not None and len(packets) >= max_packets:
                break
            block_header = f.read(8)
            if len(block_header) < 8:
                break
            block_type, block_len = struct.unpack(f"{endian}II", block_header)
            
            # Check byte order magic on Section Header Block (SHB)
            if block_type == 0x0A0D0D0A:
                shb_body = f.read(block_len - 8)
                if len(shb_body) < 8:
                    break
                bom = struct.unpack(">I", shb_body[0:4])[0]
                if bom == 0x1A2B3C4D:
                    endian = ">"
                else:
                    endian = "<"
                continue

            body_len = block_len - 8
            if body_len < 0:
                break
            block_body = f.read(body_len)
            if len(block_body) < body_len:
                break

            if block_type == 0x00000006:  # Enhanced Packet Block
                if len(block_body) < 20:
                    continue
                if endian == "<":
                    interface_id, ts_high, ts_low, caplen, origlen = struct.unpack("<IIIII", block_body[0:20])
                else:
                    interface_id, ts_high, ts_low, caplen, origlen = struct.unpack(">IIIII", block_body[0:20])

                ts = ((ts_high << 32) + ts_low) / 1e6  # Assuming microsecond resolution
                pkt_data = block_body[20: 20 + caplen]
                pkt = parse_ipv4_packet(pkt_data, ts)
                if pkt:
                    packets.append(pkt)
            elif block_type == 0x00000003:  # Simple Packet Block
                if len(block_body) < 4:
                    continue
                if endian == "<":
                    caplen = struct.unpack("<I", block_body[0:4])[0]
                else:
                    caplen = struct.unpack(">I", block_body[0:4])[0]
                pkt_data = block_body[4: 4 + caplen]
                pkt = parse_ipv4_packet(pkt_data, 0.0)
                if pkt:
                    packets.append(pkt)

    return packets


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return mean, math.sqrt(variance)


def calculate_flows(packets: list[PacketInfo]) -> dict[str, Any]:
    flow_map: dict[tuple[str, str, int, int, str], list[PacketInfo]] = {}
    
    for pkt in packets:
        # Key: (min_ip, max_ip, min_port, max_port, protocol)
        if pkt.src_ip < pkt.dst_ip:
            key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        else:
            key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)
        
        if key not in flow_map:
            flow_map[key] = []
        flow_map[key].append(pkt)

    flows = []
    protocols: dict[str, int] = {}
    unique_src = set()
    unique_dst = set()

    for idx, (key, pkts) in enumerate(flow_map.items()):
        pkts.sort(key=lambda p: p.timestamp)
        first = pkts[0]
        
        # Determine forward direction (based on initiator)
        fwd_src_ip = first.src_ip
        fwd_dst_ip = first.dst_ip
        fwd_src_port = first.src_port
        fwd_dst_port = first.dst_port
        protocol = first.protocol
        
        unique_src.add(fwd_src_ip)
        unique_dst.add(fwd_dst_ip)
        protocols[protocol] = protocols.get(protocol, 0) + 1

        duration = pkts[-1].timestamp - pkts[0].timestamp
        total_packets = len(pkts)

        fwd_pkts = [p for p in pkts if p.src_ip == fwd_src_ip]
        bwd_pkts = [p for p in pkts if p.src_ip == fwd_dst_ip]

        total_bytes = sum(p.length for p in pkts)
        fwd_bytes = sum(p.length for p in fwd_pkts)
        bwd_bytes = sum(p.length for p in bwd_pkts)

        fwd_len_mean, fwd_len_std = mean_std([float(p.length) for p in fwd_pkts])
        bwd_len_mean, bwd_len_std = mean_std([float(p.length) for p in bwd_pkts])

        # Inter-arrival times
        flow_iats = []
        for i in range(1, len(pkts)):
            flow_iats.append(pkts[i].timestamp - pkts[i - 1].timestamp)
        flow_iat_mean, flow_iat_std = mean_std(flow_iats)

        fwd_iats = []
        for i in range(1, len(fwd_pkts)):
            fwd_iats.append(fwd_pkts[i].timestamp - fwd_pkts[i - 1].timestamp)
        fwd_iat_mean, fwd_iat_std = mean_std(fwd_iats)

        bwd_iats = []
        for i in range(1, len(bwd_pkts)):
            bwd_iats.append(bwd_pkts[i].timestamp - bwd_pkts[i - 1].timestamp)
        bwd_iat_mean, bwd_iat_std = mean_std(bwd_iats)

        # TCP flags
        syn_count = sum(1 for p in pkts if p.flags & 0x02)
        ack_count = sum(1 for p in pkts if p.flags & 0x10)
        fin_count = sum(1 for p in pkts if p.flags & 0x01)
        rst_count = sum(1 for p in pkts if p.flags & 0x04)
        psh_count = sum(1 for p in pkts if p.flags & 0x08)

        # Active / Idle time (idle threshold = 5.0 seconds)
        idle_time = 0.0
        for iat in flow_iats:
            if iat > 5.0:
                idle_time += iat
        active_time = duration - idle_time

        fwd_bwd_byte_ratio = fwd_bytes / bwd_bytes if bwd_bytes > 0 else 0.0
        
        # Avoid zero duration division
        rate_duration = max(duration, 0.000001)

        flows.append({
            "flow_id": f"flw-{idx:06d}",
            "source_ip": fwd_src_ip,
            "destination_ip": fwd_dst_ip,
            "source_port": fwd_src_port,
            "destination_port": fwd_dst_port,
            "protocol": protocol,
            "start_time": datetime.fromtimestamp(pkts[0].timestamp, timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(pkts[-1].timestamp, timezone.utc).isoformat(),
            "duration": round(duration, 6),
            "total_packets": total_packets,
            "forward_packets": len(fwd_pkts),
            "backward_packets": len(bwd_pkts),
            "total_bytes": total_bytes,
            "forward_bytes": fwd_bytes,
            "backward_bytes": bwd_bytes,
            "bytes_per_second": round(total_bytes / rate_duration, 2),
            "packets_per_second": round(total_packets / rate_duration, 2),
            "fwd_pkt_len_mean": round(fwd_len_mean, 2),
            "fwd_pkt_len_std": round(fwd_len_std, 2),
            "bwd_pkt_len_mean": round(bwd_len_mean, 2),
            "bwd_pkt_len_std": round(bwd_len_std, 2),
            "flow_iat_mean": round(flow_iat_mean, 6),
            "flow_iat_std": round(flow_iat_std, 6),
            "fwd_iat_mean": round(fwd_iat_mean, 6),
            "fwd_iat_std": round(fwd_iat_std, 6),
            "bwd_iat_mean": round(bwd_iat_mean, 6),
            "bwd_iat_std": round(bwd_iat_std, 6),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "fin_count": fin_count,
            "rst_count": rst_count,
            "psh_count": psh_count,
            "fwd_bwd_byte_ratio": round(fwd_bwd_byte_ratio, 4),
            "active_time": round(active_time, 6),
            "idle_time": round(idle_time, 6),
        })

    return {
        "flows": flows,
        "statistics": {
            "total_packets": len(packets),
            "total_flows": len(flows),
            "protocols": protocols,
            "unique_src_ips": len(unique_src),
            "unique_dst_ips": len(unique_dst),
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract bidirectional flows from PCAP/PCAPNG.")
    parser.add_argument("--file", required=True, type=Path, help="Path to PCAP/PCAPNG file")
    parser.add_argument("--max-packets", type=int, help="Limit packets processed")
    args = parser.parse_args()

    if not args.file.exists():
        print(json.dumps({"error": f"File {args.file} not found"}, indent=2))
        return

    try:
        packets = read_pcap(args.file, args.max_packets)
        result = calculate_flows(packets)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(json.dumps({
            "error": f"Flow extraction failed: {e}",
            "install_instructions": "Verify file format or install standard dependencies if required: pip install scapy"
        }, indent=2))


if __name__ == "__main__":
    main()
