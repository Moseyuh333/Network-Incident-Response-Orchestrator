"""Rotate the LLM API key in .env.

This script was originally created with a hard-coded key during local
testing. That was a security mistake - the key was committed to git
history. This version does NOT contain any key. Pass it via the
``LLM_API_KEY`` environment variable or edit ``.env`` directly.

Why this script exists:
- One-line rotation of the API key (sed-style).
- Pins the model to ``models/gemini-2.5-flash-lite`` (faster, more
  quota headroom than ``gemini-2.5-flash``).
- Documents that ``gemma-4-31b-it`` is a known-broken fallback
  (returns empty text on long structured-output prompts).

Run with:
    LLM_API_KEY=<your-key> python scripts/set_new_key.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# parents[1] = scripts/ -> project root
ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
PREFERRED_MODEL = "models/gemini-2.5-flash-lite"
PLACEHOLDER = "REPLACE_ME"


def _read_key() -> str:
    """Get the API key from the environment.

    We never read or hard-code a key. Operators must pass it via
    ``LLM_API_KEY`` (or ``GOOGLE_API_KEY``) in their shell.
    """
    key = os.environ.get("LLM_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        print(
            "ERROR: no key provided.\n"
            "Set LLM_API_KEY in your shell before running this script:\n"
            "    LLM_API_KEY=<your-key> python scripts/set_new_key.py\n"
            "Or edit .env directly.\n"
        )
        sys.exit(1)
    return key.strip()


def main() -> int:
    if not ENV_PATH.exists():
        print(f".env not found at {ENV_PATH}")
        return 1
    new_key = _read_key()
    text = ENV_PATH.read_text(encoding="utf-8")
    lines = text.splitlines()
    out = []
    seen_key = False
    seen_google = False
    for line in lines:
        if line.startswith("LLM_API_KEY="):
            out.append(f"LLM_API_KEY={new_key}")
            seen_key = True
        elif line.startswith("GOOGLE_API_KEY="):
            out.append(f"GOOGLE_API_KEY={new_key}")
            seen_google = True
        else:
            out.append(line)
    if not seen_key:
        out.append(f"LLM_API_KEY={new_key}")
    if not seen_google:
        out.append(f"GOOGLE_API_KEY={new_key}")

    # Pin a working model so the live runtime does not default to the
    # broken gemma-4-31b-it.
    pinned = False
    for i, line in enumerate(out):
        if line.startswith("LLM_MODEL="):
            out[i] = f"LLM_MODEL={PREFERRED_MODEL}"
            pinned = True
    if not pinned:
        out.append(f"LLM_MODEL={PREFERRED_MODEL}")
        out.append(f"LLM_MODEL_GOOGLE={PREFERRED_MODEL}")
        out.append(f"LLM_MODEL_GEMINI={PREFERRED_MODEL}")

    ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"Updated {ENV_PATH}")
    print(f"  LLM_API_KEY updated     : {seen_key or 'appended'}")
    print(f"  GOOGLE_API_KEY updated  : {seen_google or 'appended'}")
    print(f"  PREFERRED_MODEL         : {PREFERRED_MODEL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
