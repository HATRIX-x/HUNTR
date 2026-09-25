#!/usr/bin/env bash
# Show skill usage stats — which skills produce findings vs dead ends
# Usage: ./skill-stats.sh [--top N] [--since YYYY-MM-DD]

LOG="$HOME/.claude/tools/skill-usage.log"

if [ ! -f "$LOG" ]; then
  echo "No usage data yet. Skills are tracked when you call: track-skill.sh <name> <outcome>"
  exit 0
fi

TOP="${2:-20}"
SINCE="${4:-1970-01-01}"

echo "=== Skill Performance Report ==="
echo "Log: $LOG ($(wc -l < "$LOG") entries)"
echo ""

# Count by skill + outcome
echo "--- Findings Rate by Skill ---"
echo "Skill | Loaded | Findings | No-Finding | Dup | OOS | Hit-Rate"
echo "------|--------|----------|------------|-----|-----|--------"

awk -F'\t' '{
  skill=$2; outcome=$3;
  loaded[skill]++;
  if (outcome=="finding") findings[skill]++;
  else if (outcome=="no-finding") nofind[skill]++;
  else if (outcome=="dup") dup[skill]++;
  else if (outcome=="oos") oos[skill]++;
}
END {
  for (s in loaded) {
    f = findings[s]+0;
    n = nofind[s]+0;
    d = dup[s]+0;
    o = oos[s]+0;
    l = loaded[s];
    if (l > 0) rate = int(f * 100 / l); else rate = 0;
    printf "%s\t%d\t%d\t%d\t%d\t%d\t%d%%\n", s, l, f, n, d, o, rate
  }
}' "$LOG" | sort -t$'\t' -k7 -rn | head -"$TOP" | \
  awk -F'\t' '{printf "%-40s | %6s | %8s | %10s | %3s | %3s | %s\n", $1,$2,$3,$4,$5,$6,$7}'

echo ""
echo "--- Most Loaded Skills ---"
awk -F'\t' '{print $2}' "$LOG" | sort | uniq -c | sort -rn | head -10 | \
  awk '{printf "  %3d × %s\n", $1, $2}'

echo ""
echo "--- Skills with 0 Findings (Dead Ends) ---"
awk -F'\t' '{
  skill=$2; outcome=$3;
  loaded[skill]++;
  if (outcome=="finding") findings[skill]++;
}
END {
  for (s in loaded) {
    if (findings[s]+0 == 0 && loaded[s] >= 3)
      printf "  %s (loaded %d times, 0 findings)\n", s, loaded[s]
  }
}' "$LOG" | sort

echo ""
echo "To record an outcome:"
echo "  ~/.claude/tools/track-skill.sh hunt-ssrf finding"
echo "  ~/.claude/tools/track-skill.sh hunt-graphql no-finding"
