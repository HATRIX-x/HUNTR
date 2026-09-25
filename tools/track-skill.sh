#!/usr/bin/env bash
# Skill usage tracker — append-on-invoke
# Usage: ./track-skill.sh <skill-name> [finding|no-finding|dup|oos]
# Auto-called when you load a skill during a hunt session.

LOG="$HOME/.claude/tools/skill-usage.log"
STATS="$HOME/.claude/tools/skill-stats.tsv"

skill="$1"
outcome="${2:-loaded}"  # loaded | finding | no-finding | dup | oos

if [ -z "$skill" ]; then
  echo "Usage: track-skill.sh <skill-name> [loaded|finding|no-finding|dup|oos]"
  exit 1
fi

# Append to raw log
echo "$(date -Iseconds)	$skill	$outcome" >> "$LOG"

echo "Tracked: $skill → $outcome"
