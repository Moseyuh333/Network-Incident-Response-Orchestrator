"""CLI entry point for the Network Incident Response Orchestrator."""

from __future__ import annotations

from scripts.run_pipeline import main


def run() -> None:
    """Console script wrapper."""
    main()


if __name__ == "__main__":
    run()
