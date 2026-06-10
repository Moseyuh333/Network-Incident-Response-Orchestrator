"""Collector and parser adapters."""

from app.collectors.suricata import parse_eve_file
from app.collectors.zeek import parse_zeek_file

__all__ = ["parse_eve_file", "parse_zeek_file"]
