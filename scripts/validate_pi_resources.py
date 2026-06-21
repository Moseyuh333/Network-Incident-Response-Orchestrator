"""Validation script for N.I.R.O. Pi resources (agents, skills, extensions)."""

import sys
import re
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
PI_DIR = ROOT_DIR / ".pi"

def validate_agents():
    agents_dir = PI_DIR / "agents"
    if not agents_dir.exists():
        print("[-] Agents directory does not exist.")
        return False

    errors = []
    print("[*] Validating agent profiles...")
    for p in sorted(agents_dir.glob("*.md")):
        if p.name == "agent.md":
            continue
        try:
            content = p.read_text(encoding="utf-8")
            match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
            if not match:
                errors.append(f"{p.name}: Missing YAML frontmatter delimited by ---")
                continue
            meta = yaml.safe_load(match.group(1))
            if not meta:
                errors.append(f"{p.name}: Empty YAML frontmatter")
                continue
            required = ["name", "role", "input_artifact", "output_artifact", "allowed_skills", "allowed_tools"]
            for field in required:
                if field not in meta:
                    errors.append(f"{p.name}: Missing required field '{field}' in frontmatter")
        except Exception as e:
            errors.append(f"{p.name}: Failed to parse: {e}")

    if errors:
        for err in errors:
            print(f"  [!] {err}")
        return False
    print("[+] All agent profiles are valid.")
    return True

def validate_skills():
    skills_dir = PI_DIR / "skills"
    if not skills_dir.exists():
        print("[-] Skills directory does not exist.")
        return False

    errors = []
    print("[*] Validating skills...")
    for p in sorted(skills_dir.iterdir()):
        if p.is_dir() and not p.name.startswith("."):
            manifest = p / "SKILL.md"
            if not manifest.exists():
                errors.append(f"{p.name}: Missing SKILL.md manifest")
                continue
            try:
                content = manifest.read_text(encoding="utf-8")
                match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
                if not match:
                    errors.append(f"{p.name}: SKILL.md missing frontmatter")
                    continue
                meta = yaml.safe_load(match.group(1))
                if not meta or "name" not in meta or "description" not in meta:
                    errors.append(f"{p.name}: Frontmatter must define name and description")
            except Exception as e:
                errors.append(f"{p.name}: Failed to parse SKILL.md: {e}")

            # Check for script
            scripts = [x for x in p.iterdir() if x.is_file() and x.suffix == ".py"]
            if not scripts:
                errors.append(f"{p.name}: Missing implementation python script")

    if errors:
        for err in errors:
            print(f"  [!] {err}")
        return False
    print("[+] All skills are valid.")
    return True

def main():
    agents_ok = validate_agents()
    skills_ok = validate_skills()
    if not (agents_ok and skills_ok):
        print("[-] Pi resource validation failed.")
        sys.exit(1)
    print("[+] Pi resource validation succeeded.")
    sys.exit(0)

if __name__ == "__main__":
    main()
