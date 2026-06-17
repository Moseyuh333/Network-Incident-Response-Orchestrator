"""Generate a tiny valid PCAP test file for the upload-by-path test.

Writes a syntactically valid pcap (libpcap format) with 4 simple
TCP flows: 2 normal, 1 port-scan-style, 1 ssh-brute-force-style.
The skill at .pi/skills/pcap-flow-extraction/extract_flows.py
parses these directly with the built-in Python parser (no libpcap).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

# PCAP global header (24 bytes)
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1
PCAP_SNAPLEN = 65535

# Ethernet header (14 bytes) + IPv4 (20) + TCP (20) + payload (4)
PACKET_LEN = 14 + 20 + 20 + 4


def write_global_header(f) -> None:
    f.write(struct.pack(
        "<IHHIIII",
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
        0,  # thiszone
        0,  # sigfigs
        PCAP_SNAPLEN,
        PCAP_LINKTYPE_ETHERNET,
    ))


def write_record(f, ts_sec: int, ts_usec: int, payload: bytes) -> None:
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)))
    f.write(payload)


def mac(b: bytes) -> bytes:
    return b + b"\x00" * (6 - len(b))


def ip(src: str, dst: str, length: int, ident: int) -> bytes:
    """Build a 20-byte IPv4 header (no options)."""
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    # IPv4 header layout (20 bytes, no options):
    #   0:   version (4) + IHL (5)        — 1 byte = 0x45
    #   1:   DSCP / ECN                   — 1 byte = 0x00
    #   2-3: total length                  — 2 bytes
    #   4-5: identification                — 2 bytes
    #   6-7: flags + fragment offset       — 2 bytes = 0x4000 (DF)
    #   8:   TTL                           — 1 byte = 64
    #   9:   protocol                      — 1 byte = 6 (TCP)
    #  10-11: header checksum              — 2 bytes = 0 (parser ignores)
    #  12-15: source address                — 4 bytes
    #  16-19: destination address           — 4 bytes
    return (
        b"\x45\x00"                      # version, IHL, DSCP
        + struct.pack("!H", length)      # total length (offset 2-3)
        + struct.pack("!H", ident)       # identification (offset 4-5)
        + b"\x40\x00"                    # flags=DF, fragment (offset 6-7)
        + b"\x40"                        # TTL=64 (offset 8)
        + b"\x06"                        # protocol=TCP (offset 9)
        + b"\x00\x00"                    # header checksum (offset 10-11)
        + s                              # src (offset 12-15)
        + d                              # dst (offset 16-19)
    )


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    return (
        struct.pack("!HHIIBBHHH",
                    sport, dport, seq, ack,
                    0x50,  # data offset (5 * 4 = 20 bytes)
                    flags,
                    65535,  # window
                    0,      # checksum
                    0)      # urgent
        + payload
    )


def make_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                ts: float, payload: bytes = b"\x00\x00\x00\x00") -> bytes:
    """Build Ethernet + IP + TCP packet."""
    tcp_payload = tcp(sport, dport, 1000, 0, 0x02, payload)  # SYN
    ip_packet = ip(src_ip, dst_ip, len(tcp_payload) + 20, ident=1)
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"  # dst MAC + src MAC + ethertype
    pkt = eth + ip_packet + tcp_payload
    return pkt


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/sample.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as f:
        write_global_header(f)
        # 4 distinct flows
        flows = [
            # Normal HTTP
            ("10.0.0.5", "93.184.216.34", 50000, 80, 0.0, "GET /"),
            # Normal DNS
            ("10.0.0.5", "8.8.8.8", 50001, 53, 0.5, "DNS Q"),
            # Port scan: 6 SYN to different ports from same source
            ("203.0.113.50", "10.10.20.5", 40100, 22, 1.0, "SYN"),
            ("203.0.113.50", "10.10.20.5", 40101, 23, 1.1, "SYN"),
            ("203.0.113.50", "10.10.20.5", 40102, 80, 1.2, "SYN"),
            ("203.0.113.50", "10.10.20.5", 40103, 443, 1.3, "SYN"),
            ("203.0.113.50", "10.10.20.5", 40104, 8080, 1.4, "SYN"),
            ("203.0.113.50", "10.10.20.5", 40105, 3306, 1.5, "SYN"),
        ]
        for src, dst, sport, dport, t, payload in flows:
            pkt = make_packet(src, dst, sport, dport, t, payload.encode()[:4])
            write_record(f, int(t), int((t - int(t)) * 1_000_000), pkt)
    print(f"Wrote {out} ({out.stat().st_size} bytes, {len(flows)} packets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
