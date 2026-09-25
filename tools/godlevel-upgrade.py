#!/usr/bin/env python3
"""
God-Level Skill Upgrader
Reads every hunt-* and meta skill, sends to Claude with a god-level upgrade prompt,
writes the result back. Preserves YAML frontmatter.
"""

import os
import sys
import time
import re
import argparse
from pathlib import Path

try:
    import anthropic
except ImportError:
    print("[!] pip install anthropic")
    sys.exit(1)

SKILLS_DIR = Path.home() / ".claude" / "skills"

GOD_LEVEL_PROMPT = """You are a world-class bug bounty hunter who has earned over $500k in payouts.
You are upgrading a hunting skill to GOD LEVEL. That means:

1. **Every technique has a real-world anchor** — no vague "try this", only specific payloads, exact curl commands, tool flags
2. **Failure modes documented** — for every technique, what does failure look like vs success, what false positives to avoid
3. **WAF bypass callout** — for any payload-based technique, add a WAF bypass note (encoding, header manipulation, or refer to waf-bypass-protocol)
4. **Chain discipline (FEEDER)** — end with a FEEDER section: what does confirming THIS bug unlock next? Map to the chain-builder table
5. **Never-submit gate** — add a GATE section: 3 yes/no questions the hunter must answer before submitting (based on never-submit rules)
6. **CVSS anchor** — add minimum/maximum realistic CVSS 3.1 range for each sub-technique
7. **Platform-specific notes** — add tips for HackerOne vs Intigriti vs YesWeHack vs Bugcrowd (scope differences, duplicate rates, triager behavior)
8. **Automation-first** — every manual step should have an automation alternative (nuclei template, ffuf wordlist, custom script)
9. **Real bypass patterns** — add documented real-world bypasses for common mitigations (SameSite Lax, CSP, WAF rules, rate limits)
10. **Precision impact language** — replace vague impact ("attacker could...") with exact impact with CVSS vector

The upgrade must be LONGER and MORE DETAILED than the original. Do not summarize — EXPAND.
Keep the exact same structure but make every section 2-3x more comprehensive.
Preserve the YAML frontmatter exactly. Only return the full upgraded skill file.

CURRENT SKILL:
{skill_content}

Return ONLY the upgraded skill file. No preamble. No explanation. Start with the frontmatter (---).
"""


def load_env():
    env = Path(__file__).parent / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def get_skill_files(target_skills: list[str] | None = None) -> list[Path]:
    """Get all SKILL.md files, optionally filtered."""
    skills = []
    for item in sorted(SKILLS_DIR.iterdir()):
        if item.name.startswith(".") or "backup" in item.name or item.name == "synced":
            continue
        if item.is_dir():
            skill_file = item / "SKILL.md"
            if skill_file.exists():
                if target_skills is None or item.name in target_skills:
                    skills.append(skill_file)
        elif item.suffix == ".md" and item.stem not in ["MEMORY"]:
            if target_skills is None or item.stem in target_skills:
                skills.append(item)
    return skills


def upgrade_skill(client: anthropic.Anthropic, skill_path: Path) -> tuple[bool, str]:
    """Upgrade a single skill to god level. Returns (success, message)."""
    content = skill_path.read_text(encoding="utf-8", errors="replace")

    # Skip very small files (not real skills)
    if len(content) < 500:
        return False, f"too small ({len(content)} bytes), skipping"

    # Skip already-upgraded (optional check)
    # if "## FEEDER" in content and "## GATE" in content and len(content) > 15000:
    #     return False, "already god-level, skipping"

    prompt = GOD_LEVEL_PROMPT.format(skill_content=content)

    for attempt in range(3):
        try:
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=8192,
                messages=[{"role": "user", "content": prompt}],
            )
            upgraded = msg.content[0].text.strip()

            # Validate it returned something real
            if len(upgraded) < len(content) * 0.8:
                return False, f"response too short ({len(upgraded)} vs {len(content)}), keeping original"

            # Write backup
            backup = skill_path.with_suffix(".md.bak") if skill_path.suffix == ".md" else skill_path.parent / "SKILL.md.bak"
            skill_path.rename(backup) if not backup.exists() else None

            skill_path.write_text(upgraded, encoding="utf-8")
            size_before = len(content)
            size_after = len(upgraded)
            return True, f"{size_before}→{size_after} bytes (+{size_after-size_before})"

        except anthropic.RateLimitError:
            wait = 60 * (attempt + 1)
            print(f"  [rate limit] waiting {wait}s...")
            time.sleep(wait)
        except anthropic.APIError as e:
            return False, f"API error: {e}"
        except Exception as e:
            return False, f"error: {e}"

    return False, "failed after 3 attempts"


def main():
    parser = argparse.ArgumentParser(description="Upgrade skills to god level")
    parser.add_argument("skills", nargs="*", help="Specific skill names to upgrade (default: all)")
    parser.add_argument("--dry-run", action="store_true", help="List skills without upgrading")
    parser.add_argument("--priority", action="store_true", help="Only upgrade hunt-* and meta skills")
    parser.add_argument("--min-size", type=int, default=1000, help="Min bytes to upgrade (default: 1000)")
    args = parser.parse_args()

    load_env()
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("[!] Set ANTHROPIC_API_KEY in ~/.claude/tools/.env")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    target_skills = args.skills if args.skills else None
    skill_files = get_skill_files(target_skills)

    if args.priority:
        skill_files = [f for f in skill_files if
                       any(f.parent.name.startswith(p) or f.stem.startswith(p)
                           for p in ["hunt-", "chain-", "waf-", "never-", "report-", "recon-", "web2-", "bb-"])]

    # Filter by size
    skill_files = [f for f in skill_files if f.stat().st_size >= args.min_size]

    print(f"[*] Skills to upgrade: {len(skill_files)}")
    if args.dry_run:
        for f in skill_files:
            skill_name = f.parent.name if f.name == "SKILL.md" else f.stem
            print(f"  {skill_name} ({f.stat().st_size} bytes)")
        return

    upgraded = 0
    failed = 0
    skipped = 0

    for i, skill_path in enumerate(skill_files, 1):
        skill_name = skill_path.parent.name if skill_path.name == "SKILL.md" else skill_path.stem
        print(f"[{i}/{len(skill_files)}] Upgrading: {skill_name}...", end=" ", flush=True)

        success, msg = upgrade_skill(client, skill_path)
        if success:
            upgraded += 1
            print(f"✓ {msg}")
        elif "skipping" in msg or "too small" in msg:
            skipped += 1
            print(f"~ {msg}")
        else:
            failed += 1
            print(f"✗ {msg}")

        # Rate limiting — be nice to the API
        time.sleep(2)

    print(f"\n[+] Done: {upgraded} upgraded, {skipped} skipped, {failed} failed")
    print(f"[+] Skills dir: {SKILLS_DIR}")


if __name__ == "__main__":
    main()
