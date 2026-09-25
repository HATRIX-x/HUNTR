#!/usr/bin/env bash
# session-plan.sh — Generate a systematic attack methodology for any target
# Usage: ./session-plan.sh
# Or:    ./session-plan.sh --target TARGET_URL --platform h1 --scope web --auth grey --stack nextjs --bounty 10k --competition new --industry saas

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── Defaults ──────────────────────────────────────────────────────────────────
TARGET=""
PLATFORM=""
SCOPE=""
AUTH=""
STACK=""
BOUNTY=""
COMPETITION=""
INDUSTRY=""

# ─── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)      TARGET="$2";      shift 2 ;;
    --platform)    PLATFORM="$2";    shift 2 ;;
    --scope)       SCOPE="$2";       shift 2 ;;
    --auth)        AUTH="$2";        shift 2 ;;
    --stack)       STACK="$2";       shift 2 ;;
    --bounty)      BOUNTY="$2";      shift 2 ;;
    --competition) COMPETITION="$2"; shift 2 ;;
    --industry)    INDUSTRY="$2";    shift 2 ;;
    *) shift ;;
  esac
done

# ─── Interactive prompts if not provided ───────────────────────────────────────
echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║     Bug Bounty Session Planner               ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""

if [ -z "$TARGET" ]; then
  read -rp "Target URL or program name: " TARGET
fi

if [ -z "$PLATFORM" ]; then
  echo "Platform: [1] HackerOne  [2] YesWeHack  [3] Intigriti  [4] Bugcrowd  [5] BUGEX  [6] Private"
  read -rp "Choice [1-6]: " p
  case "$p" in
    1) PLATFORM="h1" ;; 2) PLATFORM="ywh" ;; 3) PLATFORM="intigriti" ;;
    4) PLATFORM="bugcrowd" ;; 5) PLATFORM="bugex" ;; *) PLATFORM="private" ;;
  esac
fi

if [ -z "$SCOPE" ]; then
  echo "Scope type: [1] Web  [2] API  [3] Mobile  [4] Cloud  [5] Source Code  [6] Mixed"
  read -rp "Choice [1-6]: " s
  case "$s" in
    1) SCOPE="web" ;; 2) SCOPE="api" ;; 3) SCOPE="mobile" ;;
    4) SCOPE="cloud" ;; 5) SCOPE="source" ;; *) SCOPE="mixed" ;;
  esac
fi

if [ -z "$AUTH" ]; then
  echo "Auth level: [1] Black Box (no account)  [2] Grey Box (has account)  [3] White Box (source)"
  read -rp "Choice [1-3]: " a
  case "$a" in
    1) AUTH="black" ;; 2) AUTH="grey" ;; *) AUTH="white" ;;
  esac
fi

if [ -z "$STACK" ]; then
  echo "Tech stack (leave blank if unknown):"
  echo "  [1] React/Next.js  [2] Angular/Vue  [3] PHP/Laravel  [4] Java/Spring"
  echo "  [5] Python/Django  [6] Ruby/Rails   [7] .NET/ASP     [8] Node.js  [9] Unknown"
  read -rp "Choice [1-9]: " t
  case "$t" in
    1) STACK="nextjs" ;; 2) STACK="angular" ;; 3) STACK="laravel" ;;
    4) STACK="spring" ;; 5) STACK="django" ;; 6) STACK="rails" ;;
    7) STACK="aspnet" ;; 8) STACK="nodejs" ;; *) STACK="unknown" ;;
  esac
fi

if [ -z "$BOUNTY" ]; then
  echo "Max bounty range: [1] <$500  [2] $500-2k  [3] $2k-10k  [4] $10k-50k  [5] $50k+"
  read -rp "Choice [1-5]: " b
  case "$b" in
    1) BOUNTY="low" ;; 2) BOUNTY="medium" ;; 3) BOUNTY="high" ;;
    4) BOUNTY="veryhigh" ;; *) BOUNTY="critical" ;;
  esac
fi

if [ -z "$COMPETITION" ]; then
  echo "Program age / competition: [1] New (<30 days)  [2] Active (30-90d)  [3] Well-mined (90d+)"
  read -rp "Choice [1-3]: " c
  case "$c" in
    1) COMPETITION="new" ;; 2) COMPETITION="active" ;; *) COMPETITION="mined" ;;
  esac
fi

if [ -z "$INDUSTRY" ]; then
  echo "Industry: [1] Fintech  [2] SaaS/B2B  [3] Gaming  [4] Healthcare  [5] Gov/Enterprise"
  echo "          [6] Crypto/Web3  [7] E-commerce  [8] Other"
  read -rp "Choice [1-8]: " i
  case "$i" in
    1) INDUSTRY="fintech" ;; 2) INDUSTRY="saas" ;; 3) INDUSTRY="gaming" ;;
    4) INDUSTRY="healthcare" ;; 5) INDUSTRY="enterprise" ;; 6) INDUSTRY="crypto" ;;
    7) INDUSTRY="ecommerce" ;; *) INDUSTRY="other" ;;
  esac
fi

# ─── Determine Template ────────────────────────────────────────────────────────
TEMPLATE=""
TIME_BUDGET=""

if [ "$SCOPE" = "mobile" ]; then
  TEMPLATE="H"; TIME_BUDGET="5h"
elif [ "$SCOPE" = "source" ] || [ "$AUTH" = "white" ]; then
  TEMPLATE="F"; TIME_BUDGET="8h"
elif [ "$INDUSTRY" = "crypto" ]; then
  TEMPLATE="G"; TIME_BUDGET="6h"
elif [ "$INDUSTRY" = "fintech" ]; then
  TEMPLATE="E"; TIME_BUDGET="8h"
elif [ "$SCOPE" = "api" ]; then
  TEMPLATE="C"; TIME_BUDGET="5h"
elif [ "$SCOPE" = "web" ] && [ "$AUTH" = "grey" ]; then
  TEMPLATE="B"; TIME_BUDGET="6h"
elif [ "$SCOPE" = "web" ] || [ "$SCOPE" = "mixed" ]; then
  TEMPLATE="A"; TIME_BUDGET="4h"
else
  TEMPLATE="A"; TIME_BUDGET="4h"
fi

# Override for GraphQL (check by stack signal - user can specify)
[ "$STACK" = "graphql" ] && TEMPLATE="D" && TIME_BUDGET="3h"

# ─── Competition Modifier ──────────────────────────────────────────────────────
SPEED_NOTE=""
case "$COMPETITION" in
  new)    SPEED_NOTE="${GREEN}SPEED MODE: New program — submit same day, hit obvious bugs first${RESET}" ;;
  active) SPEED_NOTE="${YELLOW}FOCUSED MODE: Active program — logic bugs + authenticated surfaces only${RESET}" ;;
  mined)  SPEED_NOTE="${RED}CHAIN MODE: Well-mined — single bugs = duplicates, chains only pay${RESET}" ;;
esac

# ─── ROI Pre-Check ─────────────────────────────────────────────────────────────
ROI_WARN=""
[ "$BOUNTY" = "low" ] && ROI_WARN="${RED}⚠ LOW BOUNTY CAP: Expected <$50/hr. Consider pivoting after 2h if no finding.${RESET}"

# ─── Skill Priority List ───────────────────────────────────────────────────────
declare -A TEMPLATE_SKILLS
TEMPLATE_SKILLS["A"]="hunt-program-intel → recon-scope-triage → hunt-js-analysis → hunt-dispatch-table → hunt-${STACK} → hunt-oauth → hunt-jwt-crypto → hunt-forgot-password → hunt-open-redirect → hunt-source-leak → triage-validation → report-writing"
TEMPLATE_SKILLS["B"]="hunt-program-intel → recon-scope-triage → hunt-js-analysis → hunt-idor → hunt-business-logic → hunt-race-condition → hunt-auth-bypass → hunt-oauth → hunt-mfa-bypass → hunt-sqli → hunt-ssti → hunt-xxe → chain-builder → triage-validation → report-writing"
TEMPLATE_SKILLS["C"]="hunt-shadow-api → hunt-js-analysis → hunt-jwt-crypto → hunt-oauth → hunt-idor → hunt-api-misconfig → hunt-sqli → hunt-nosqli → hunt-graphql → hunt-ssrf → hunt-xxe → chain-builder → triage-validation"
TEMPLATE_SKILLS["D"]="hunt-graphql → hunt-fintech-graphql → hunt-idor → hunt-sqli → hunt-ssrf → hunt-ssti → chain-builder → triage-validation"
TEMPLATE_SKILLS["E"]="hunt-program-intel → recon-scope-triage → hunt-js-analysis → hunt-oauth → hunt-mfa-bypass → hunt-jwt-crypto → hunt-business-logic → hunt-race-condition → hunt-fintech-graphql → hunt-idor → hunt-sqli → hunt-ssrf → hunt-xxe → hunt-jwt-crypto → chain-builder → report-writing"
TEMPLATE_SKILLS["F"]="supply-chain-attack-recon → hunt-source-leak → hunt-prototype-pollution → hunt-sqli → hunt-ssti → hunt-xxe → hunt-deserialization → hunt-auth-bypass → chain-builder → triage-validation → report-writing"
TEMPLATE_SKILLS["G"]="hunt-program-intel → recon-scope-triage → hunt-js-analysis → web3-audit → hunt-api-misconfig → hunt-jwt-crypto → chain-builder → triage-validation"
TEMPLATE_SKILLS["H"]="apk-redteam-pipeline → ios-redteam-pipeline → hunt-js-analysis → hunt-idor → hunt-business-logic → hunt-jwt-crypto → triage-validation → report-writing"

# Stack-specific first skill
STACK_SKILL=""
case "$STACK" in
  nextjs)   STACK_SKILL="hunt-nextjs" ;;
  laravel)  STACK_SKILL="hunt-laravel" ;;
  spring)   STACK_SKILL="hunt-springboot" ;;
  aspnet)   STACK_SKILL="hunt-aspnet" ;;
  django)   STACK_SKILL="hunt-django" ;;
  nodejs)   STACK_SKILL="hunt-nodejs" ;;
  rails)    STACK_SKILL="hunt-rails" ;;
  *)        STACK_SKILL="hunt-exceptional-conditions" ;;
esac

# ─── Output Plan ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  SESSION PLAN: $TARGET${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Platform:     ${CYAN}$PLATFORM${RESET}"
echo -e "  Scope:        ${CYAN}$SCOPE${RESET}"
echo -e "  Auth:         ${CYAN}$AUTH${RESET}"
echo -e "  Stack:        ${CYAN}$STACK${RESET}  → ${YELLOW}$STACK_SKILL${RESET}"
echo -e "  Bounty cap:   ${CYAN}$BOUNTY${RESET}"
echo -e "  Competition:  ${CYAN}$COMPETITION${RESET}"
echo -e "  Industry:     ${CYAN}$INDUSTRY${RESET}"
echo ""
echo -e "  Template:     ${GREEN}${BOLD}$TEMPLATE${RESET}  |  Time budget: ${BOLD}$TIME_BUDGET${RESET}"
echo ""
[ -n "$SPEED_NOTE" ] && echo -e "  $SPEED_NOTE"
[ -n "$ROI_WARN" ]   && echo -e "  $ROI_WARN"
echo ""

echo -e "${BOLD}─── SKILL LOAD ORDER ─────────────────────────────${RESET}"
echo "${TEMPLATE_SKILLS[$TEMPLATE]}" | tr '→' '\n' | tr -d ' ' | grep -v '^$' | awk '{printf "  %2d. %s\n", NR, $1}'
echo ""

echo -e "${BOLD}─── STACK-SPECIFIC ADDITION ──────────────────────${RESET}"
echo -e "  Load after JS analysis: ${YELLOW}$STACK_SKILL${RESET}"
echo ""

echo -e "${BOLD}─── INDUSTRY PRIORITY ────────────────────────────${RESET}"
case "$INDUSTRY" in
  fintech)    echo -e "  ${RED}PRIORITY: hunt-business-logic → hunt-race-condition → hunt-idor (financial objects)${RESET}" ;;
  healthcare) echo -e "  ${RED}PRIORITY: hunt-idor (patient IDs) → hunt-auth-bypass → hunt-ssrf${RESET}" ;;
  saas)       echo -e "  ${YELLOW}PRIORITY: hunt-idor (tenant isolation) → hunt-auth-bypass → hunt-business-logic${RESET}" ;;
  gaming)     echo -e "  ${YELLOW}PRIORITY: hunt-business-logic (currency/items) → hunt-race-condition → hunt-idor${RESET}" ;;
  enterprise) echo -e "  ${YELLOW}PRIORITY: hunt-auth-bypass → okta-attack OR m365-entra-attack → hunt-idor${RESET}" ;;
  crypto)     echo -e "  ${RED}PRIORITY: web3-audit → hunt-business-logic → hunt-api-misconfig${RESET}" ;;
  ecommerce)  echo -e "  ${YELLOW}PRIORITY: hunt-business-logic (price) → hunt-race-condition → hunt-idor${RESET}" ;;
  *)          echo -e "  Standard priority — follow template order" ;;
esac
echo ""

echo -e "${BOLD}─── 2-HOUR ROI GATE ──────────────────────────────${RESET}"
echo "  After 2 hours, ask:"
echo "  [ ] Found ≥1 confirmed finding?"
echo "  [ ] Blocked by auth I don't have?"
echo "  [ ] Duplicate risk < 60%?"
echo "  [ ] Expected ROI > \$50/hour?"
echo "  → If 2+ NO answers: pivot to a different program"
echo ""

echo -e "${BOLD}─── NEVER SUBMIT REMINDER ────────────────────────${RESET}"
echo "  Load SKILL: never-submit before writing any report"
echo "  Load SKILL: triage-validation to confirm before submitting"
echo ""

# Save plan to file
PLAN_FILE="$HOME/.claude/tools/session_plans/$(date +%Y%m%d_%H%M%S)_$(echo "$TARGET" | tr '/:.' '_').txt"
mkdir -p "$HOME/.claude/tools/session_plans"

{
  echo "Target: $TARGET"
  echo "Date: $(date)"
  echo "Platform: $PLATFORM | Scope: $SCOPE | Auth: $AUTH | Stack: $STACK"
  echo "Bounty: $BOUNTY | Competition: $COMPETITION | Industry: $INDUSTRY"
  echo "Template: $TEMPLATE | Budget: $TIME_BUDGET"
  echo ""
  echo "Skill order:"
  echo "${TEMPLATE_SKILLS[$TEMPLATE]}" | tr '→' '\n' | awk '{printf "  %d. %s\n", NR, $1}'
  echo ""
  echo "Stack skill: $STACK_SKILL"
} > "$PLAN_FILE"

echo -e "  ${GREEN}Plan saved: $PLAN_FILE${RESET}"
echo ""
