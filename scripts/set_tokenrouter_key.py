"""One-shot helper: write the TokenRouter credentials into .env.

Run by the operator after cloning; never include the key in source.
"""

from pathlib import Path

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
NEW_KEY = "sk-hovIVdrbC75qUuWwWqqHc5vyBJh3k4mzkeij9Olr90DnvQh6"
NEW_BASE = "https://api.tokenrouter.com/v1"
NEW_MODEL = "MiniMax-M3"

CONFIG = {
    "LLM_PROVIDER": "tokenrouter",
    "LLM_API_KEY": NEW_KEY,
    "GOOGLE_API_KEY": NEW_KEY,  # keep parity for any fallback code
    "LLM_API_BASE": NEW_BASE,
    "LLM_MODEL": NEW_MODEL,
    "LLM_MODEL_GOOGLE": NEW_MODEL,
    "LLM_MODEL_GEMINI": NEW_MODEL,
    "LLM_MODEL_TOKENROUTER": NEW_MODEL,
}


def main() -> int:
    if not ENV_PATH.exists():
        print(f".env not found at {ENV_PATH}")
        return 1
    text = ENV_PATH.read_text(encoding="utf-8")
    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line else None
        if key and key in CONFIG:
            out.append(f"{key}={CONFIG[key]}")
            seen.add(key)
        else:
            out.append(line)
    for k, v in CONFIG.items():
        if k not in seen:
            out.append(f"{k}={v}")
    ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"Updated {ENV_PATH}")
    for k in CONFIG:
        val = CONFIG[k]
        masked = (val[:4] + "..." + val[-2:]) if len(val) > 8 and "sk-" in val else val
        print(f"  {k:30s} = {masked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
