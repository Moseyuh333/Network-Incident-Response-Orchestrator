"""Cheap reachability check for the LLM provider.

Run this first to confirm your key, model, and quota are healthy
before burning tokens on the full scenario suite.

    python -m tests.llm_integration.probe
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = HERE.parent.parent
for p in (str(_PROJECT_ROOT), str(HERE.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from app.llm.providers import GoogleGenAIProvider  # noqa: E402


def main() -> int:
    provider = GoogleGenAIProvider()
    print(f"Provider : {provider.provider_name}")
    print(f"Model    : {provider.model}")
    print(f"Configured: {provider.is_configured}")
    if not provider.is_configured:
        print("Set LLM_API_KEY or GOOGLE_API_KEY in .env to enable LLM tests.")
        return 1

    print("\nSending a tiny probe ('Reply with just the word: ok')...")
    started = time.monotonic()
    result = provider.generate("Reply with just the word: ok")
    elapsed = time.monotonic() - started
    print(f"Latency  : {elapsed:.2f}s")
    print(f"Available: {result.available}")
    print(f"Response : {result.text!r}")
    if not result.available:
        print(f"Reason   : {result.fallback_reason}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
