#!/usr/bin/env bash
# God-Level Skill Upgrader — uses claude CLI (OAuth, no API key needed)
# Usage: ./godlevel-upgrade.sh [skill-name ...] [--priority] [--dry-run]
# Examples:
#   ./godlevel-upgrade.sh                          # upgrade all
#   ./godlevel-upgrade.sh hunt-cors hunt-jwt-crypto # upgrade specific
#   ./godlevel-upgrade.sh --priority               # only hunt-* and meta skills
#   ./godlevel-upgrade.sh --dry-run                # list without upgrading

set -euo pipefail

SKILLS_DIR="$HOME/.claude/skills"
LOG="$HOME/.claude/tools/godlevel-upgrade.log"
DRY_RUN=false
PRIORITY_ONLY=false
TARGET_SKILLS=()

for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY_RUN=true ;;
    --priority)  PRIORITY_ONLY=true ;;
    *)           TARGET_SKILLS+=("$arg") ;;
  esac
done

UPGRADE_PROMPT='You are a world-class bug bounty hunter with $500k+ in payouts. Upgrade this skill to GOD LEVEL:

RULES:
1. Every technique needs exact payloads/commands (no vague "try this")
2. Add FAILURE MODES — what does failure look like vs success, false positive traps
3. Add WAF BYPASS NOTE for every payload-based technique (encoding variants, header manipulation)
4. Add ## FEEDER section at the end: what does confirming this bug unlock next? (chain to ATO/RCE/data-breach)
5. Add ## GATE (3 yes/no questions hunter must answer YES to before submitting)
6. Add CVSS 3.1 range (min/max realistic) per sub-technique
7. Add ## PLATFORM NOTES: HackerOne vs Intigriti vs YesWeHack vs Bugcrowd differences
8. Every manual step gets an automation alternative (nuclei/ffuf/custom script)
9. Add real documented bypasses for common defenses (SameSite Lax, CSP, WAF, rate limits)
10. Replace all vague impact language with exact impact + CVSS vector string

MAKE IT 2-3x LONGER. EXPAND every section. Keep YAML frontmatter EXACTLY.
Return ONLY the upgraded skill. No preamble. Start with ---'

upgrade_skill() {
  local skill_path="$1"
  local skill_name

  if [[ "$(basename "$skill_path")" == "SKILL.md" ]]; then
    skill_name=$(basename "$(dirname "$skill_path")")
  else
    skill_name=$(basename "$skill_path" .md)
  fi

  local size
  size=$(wc -c < "$skill_path")

  if [ "$size" -lt 1000 ]; then
    echo "  ~ $skill_name: too small (${size}B), skipping"
    return
  fi

  if $DRY_RUN; then
    echo "  [dry-run] $skill_name (${size}B)"
    return
  fi

  echo -n "  Upgrading $skill_name (${size}B)... "

  # Build the full prompt with skill content
  local content
  content=$(cat "$skill_path")

  local upgraded
  if ! upgraded=$(echo "$UPGRADE_PROMPT

SKILL TO UPGRADE:
$content" | claude -p 2>/dev/null); then
    echo "✗ claude CLI failed"
    echo "[$(date)] FAILED: $skill_name" >> "$LOG"
    return
  fi

  if [ ${#upgraded} -lt $((size / 2)) ]; then
    echo "✗ response too short (${#upgraded}B vs ${size}B)"
    echo "[$(date)] TOO_SHORT: $skill_name" >> "$LOG"
    return
  fi

  # Backup original
  if [ ! -f "${skill_path}.bak" ]; then
    cp "$skill_path" "${skill_path}.bak"
  fi

  echo "$upgraded" > "$skill_path"
  local new_size
  new_size=$(wc -c < "$skill_path")
  local delta=$((new_size - size))
  echo "✓ ${size}B → ${new_size}B (+${delta}B)"
  echo "[$(date)] OK: $skill_name ${size}→${new_size}" >> "$LOG"

  # Rate limit — avoid hammering claude CLI
  sleep 3
}

# Collect skill paths
SKILL_PATHS=()

for item in "$SKILLS_DIR"/*/; do
  skill_name=$(basename "$item")
  [[ "$skill_name" == *backup* ]] && continue
  [[ "$skill_name" == "synced" ]] && continue

  skill_file="$item/SKILL.md"
  [ -f "$skill_file" ] || continue

  if $PRIORITY_ONLY; then
    case "$skill_name" in
      hunt-*|chain-*|waf-*|never-*|report-*|recon-*|web2-*|bb-*|triage-*) ;;
      *) continue ;;
    esac
  fi

  if [ ${#TARGET_SKILLS[@]} -gt 0 ]; then
    found=false
    for t in "${TARGET_SKILLS[@]}"; do
      [[ "$skill_name" == "$t" ]] && found=true && break
    done
    $found || continue
  fi

  SKILL_PATHS+=("$skill_file")
done

# Also handle flat .md skills
for item in "$SKILLS_DIR"/*.md; do
  [ -f "$item" ] || continue
  skill_name=$(basename "$item" .md)
  [[ "$skill_name" == "MEMORY" ]] && continue

  if [ ${#TARGET_SKILLS[@]} -gt 0 ]; then
    found=false
    for t in "${TARGET_SKILLS[@]}"; do
      [[ "$skill_name" == "$t" ]] && found=true && break
    done
    $found || continue
  fi

  SKILL_PATHS+=("$item")
done

echo "[*] Skills to upgrade: ${#SKILL_PATHS[@]}"
echo "[$(date)] Starting god-level upgrade: ${#SKILL_PATHS[@]} skills" >> "$LOG"

upgraded=0
failed=0
skipped=0

for skill_path in "${SKILL_PATHS[@]}"; do
  upgrade_skill "$skill_path"
done

echo ""
echo "[+] God-level upgrade complete"
echo "[+] Log: $LOG"
