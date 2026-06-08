from __future__ import annotations

import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parent / "Topic_09_Network_Incident_Response_Orchestrator.zip"
EXCLUDE_PARTS = {".git", "__pycache__", ".pytest_cache"}


def should_include(path: Path) -> bool:
    return not any(part in EXCLUDE_PARTS for part in path.parts)


def main() -> int:
    if OUTPUT.exists():
        OUTPUT.unlink()
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in ROOT.rglob("*"):
            if path.is_file() and should_include(path.relative_to(ROOT)):
                archive.write(path, path.relative_to(ROOT.parent))
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
