"""Generate a tiny synthetic PCAP for testing the by-path PCAP endpoint."""

import ipaddress
import struct
from pathlib import Path

# libpcap global header: magic, version 2.4, thiszone, sigfigs, snaplen, linktype
GLOBAL_HEADER = struct.pack(
    "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
)


def eth_ip_tcp(src: str, dst: str, sport: int, dport: int) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP frame (no checksums, no options)."""
    src_b = ipaddress.IPv4Address(src).packed
    dst_b = ipaddress.IPv4Address(dst).packed

    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
    payload = b"GET / HTTP/1.0\r\n\r\n"
    ip_total_len = 20 + 20 + len(payload)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, ip_total_len,
        0x1234, 0,
        64, 6, 0,
        src_b, dst_b,
    )
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1000, 0, 0x50, 0x18, 8192, 0, 0)
    return eth + ip + tcp + payload


def main() -> None:
    out = Path(__file__).parent / "sample.pcap"
    pcap = bytearray(GLOBAL_HEADER)
    ts = 1718553600
    flows = [
        ("192.168.1.50", "10.0.0.10", 54321, 22),
        ("192.168.1.50", "10.0.0.10", 54322, 22),
        ("10.0.0.5", "8.8.8.8", 12345, 53),
        ("10.0.0.5", "203.0.113.50", 33333, 80),
        ("10.0.0.5", "203.0.113.50", 33334, 443),
        ("10.0.0.5", "203.0.113.50", 33335, 80),
    ]
    for i, (s, d, sp, dp) in enumerate(flows):
        pkt = eth_ip_tcp(s, d, sp, dp)
        pcap += struct.pack("<IIII", ts + i, 0, len(pkt), len(pkt))
        pcap += pkt
    out.write_bytes(bytes(pcap))
    print(f"Wrote {out} ({len(pcap)} bytes, {len(flows)} packets)")


if __name__ == "__main__":
    main()
