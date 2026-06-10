"""Central paths for the application — used by scripts, API, and web UI."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PI_DIR = ROOT / ".pi"
DATA_DIR = PI_DIR / "data"
TRIAGE_DIR = PI_DIR / "triage"
LOG_DIR = PI_DIR / "logs"
REPORT_DIR = PI_DIR / "reports"

__all__ = ["ROOT", "PI_DIR", "DATA_DIR", "TRIAGE_DIR", "LOG_DIR", "REPORT_DIR"]
