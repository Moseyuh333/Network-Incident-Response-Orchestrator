"""Validation script for N.I.R.O. orchestration chains."""

import sys
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
CHAINS_DIR = ROOT_DIR / ".pi" / "chains"

def validate_chains():
    if not CHAINS_DIR.exists():
        print("[-] Chains directory does not exist.")
        return False

    errors = []
    print("[*] Validating chain configurations...")
    for p in sorted(CHAINS_DIR.glob("*.yaml")):
        try:
            content = yaml.safe_load(p.read_text(encoding="utf-8"))
            if not content:
                errors.append(f"{p.name}: Empty chain definition")
                continue
            if "chain" not in content and "phases" not in content and "steps" not in content:
                errors.append(f"{p.name}: Missing key 'chain', 'phases', or 'steps'")
        except Exception as e:
            errors.append(f"{p.name}: YAML parsing error: {e}")

    if errors:
        for err in errors:
            print(f"  [!] {err}")
        return False
    print("[+] All orchestration chains are valid.")
    return True

def main():
    if not validate_chains():
        print("[-] Chain validation failed.")
        sys.exit(1)
    print("[+] Chain validation succeeded.")
    sys.exit(0)

if __name__ == "__main__":
    main()
