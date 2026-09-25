#!/usr/bin/env bash
# Self-learning skill updater — runs weekly via cron or manually
# Fetches new public HackerOne reports and regenerates hunt-* skills
# Usage: ./update-skills.sh [vuln-type idor ssrf xss ...]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DIR="$HOME/.claude/skills"
BUILDER="$SCRIPT_DIR/skill-builder.py"
OUT_DIR="$SCRIPT_DIR/generated-skills"
LOG="$SCRIPT_DIR/update.log"

echo "[$(date)] Starting skill update..." | tee -a "$LOG"

# Load env
[ -f "$SCRIPT_DIR/.env" ] && export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "[!] ANTHROPIC_API_KEY not set in $SCRIPT_DIR/.env" | tee -a "$LOG"
    exit 1
fi

# Run the builder
if [ $# -gt 0 ]; then
    python3 "$BUILDER" --source h1-public --limit 300 --out "$OUT_DIR" --vuln-type "$@" 2>&1 | tee -a "$LOG"
else
    python3 "$BUILDER" --source h1-public --limit 500 --out "$OUT_DIR" 2>&1 | tee -a "$LOG"
fi

# Merge generated skills into the skills directory
UPDATED=0
for skill_file in "$OUT_DIR"/hunt-*.md; do
    [ -f "$skill_file" ] || continue
    skill_name=$(basename "$skill_file" .md)
    target_dir="$SKILLS_DIR/$skill_name"

    # Only update if we have the skill already (don't create new directories for generated files)
    if [ -d "$target_dir" ]; then
        # Append new patterns to the existing SKILL.md as an appendix
        if ! grep -q "## Auto-updated Patterns" "$target_dir/SKILL.md" 2>/dev/null; then
            echo "" >> "$target_dir/SKILL.md"
            echo "---" >> "$target_dir/SKILL.md"
            echo "## Auto-updated Patterns ($(date +%Y-%m-%d))" >> "$target_dir/SKILL.md"
            cat "$skill_file" | grep -A200 "## Crown Jewel" | head -50 >> "$target_dir/SKILL.md"
            UPDATED=$((UPDATED + 1))
            echo "[+] Updated: $skill_name" | tee -a "$LOG"
        fi
    else
        # New skill — install it as a flat file (not a directory)
        cp "$skill_file" "$target_dir"
        UPDATED=$((UPDATED + 1))
        echo "[+] Installed new skill: $skill_name" | tee -a "$LOG"
    fi
done

echo "[$(date)] Done. $UPDATED skills updated." | tee -a "$LOG"
