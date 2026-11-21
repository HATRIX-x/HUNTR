# HUNTR Roadmap — beating XBOW on its own axes

Goal: win the 7 dimensions where XBOW currently leads (autonomy, exploitation
depth, browser-native exploitation, throughput/scale, learning-loop/moat,
engineering robustness, compliance/enterprise fit) **without** trying to
out-fund or out-scale them. Every phase routes through one of HUNTR's three
structural advantages: runs on the *user's* compute, every finding is
*human-adjudicated* (clean corpus), and it's *Claude-native and open*.

Build order is dependency-driven, not value-driven: robustness first because
autonomy and enterprise sit on top of it; the free/private moats next; the
depth and upmarket plays last.

Legend: ☐ todo · ◧ in progress · ☑ done (verified)

---

## Phase 0 — Robustness foundation  (axis: Engineering robustness)
*Why first: autonomous and enterprise both assume the thing doesn't fall over.
No asymmetry here — just discipline. It is the prerequisite for Phases 3 and 6.*

- ☑ **0.1** Wire Playwright E2E + server-hardening tests into CI
  (`.github/workflows/ci.yml` gains an `e2e` job; the `test` job runs the new
  `tests/test_server_hardening.py`). "Crashes on garbage input" can't regress.
  - Verified: `make verify` green locally (compile + 54 tests + 7 E2E); CI runs
    the same on push/PR.
- ◧ **0.2** Collapse duplicated helpers into `huntrlib`.
  - Done: the drifted/buggy `safe()` copies were reconciled (commit 56965c7) and
    canonical `safe/arg/flag/args_multi` live in `huntrlib`.
  - **Deliberately deferred (non-goal):** mass-migrating all ~90 standalone tools
    to `import huntrlib`. They're designed to run independently without a
    guaranteed import path; a blanket rewrite trades robustness for DRY. Revisit
    only if a packaged distribution makes the import path reliable.
- ☑ **0.3** Server hardening pass: non-dict body guard, Content-Length guard,
  413 drain, base64 guard, blank-target/no-target rejects — no raw tracebacks,
  structured 4xx (commit f08c9fd).
  - Verified: stress battery 0 flagged / 0 tracebacks; locked by
    `test_server_hardening.py`.
- ☑ **0.4** `/api/health` endpoint (uptime + port + active-hunt count).
  - Verified: `test_health_reports_liveness`.

**Exit gate:** ☑ `make verify` (new Makefile) runs compile + unit/integration
tests + Playwright and exits non-zero on any failure. CI enforces it.

---

## Phase 1.5 — Deterministic scope intake  (prerequisite for autonomy)
*The intake was a client-side, LLM-only, button-dependent coin flip: "Confirm &
summarize" ran an LLM parse, while "Start hunt" on a raw page fed the whole page
to hunt-run.py --target, which whitespace-split it into hundreds of junk assets.
Autonomy is impossible if step one is that unreliable.*

- ☑ `tools/scope_ingest.py`: one pipeline — detect shape → **deterministic** asset
  extract (hosts/URLs/CIDRs/repos, typed web/api/mobile/source, in/out-of-scope
  split) → optional LLM enrich of metadata only (rewards/rules/caps, and only when
  creds exist) → canonicalize/dedup → persist `scope.allow`/`scope.deny`/`program.json`.
- ☑ Wired `/api/scope/parse` and `/api/hunt/start` through it, so a pasted page
  never reaches `hunt-run.py --target` as raw text again.
  - Verified (`tests/test_scope_ingest.py` 9 + server integration): a full program
    page yields exactly the real assets, correctly typed and in/out-split, with
    **zero prose junk** — no LLM needed. Live run confirmed LLM enrich fills
    metadata while the asset list stays deterministic.

## Phase 1 — Outcome-labeled corpus  (axis: Learning loop / data moat)
*Why second: cheapest high-leverage moat; the funnel data already exists, just
not fed back. Turns "we submitted X" (XBOW) into "X got paid/rejected" (us).*

- ☑ **1.1** `funnel.py --sync-outcomes` bridges terminal funnel adjudications
  (accepted/dupe/rejected/paid + payout) into the `outcome-check` learning store,
  idempotently (dedup by `src_funnel_id`). New shared helper `tools/outcome_priors.py`.
- ☑ **1.2** `finding-pipeline` consults learned priors (`fp_signal`) and caps a
  historically-rejected class so it can never auto-SUBMIT — down-ranked to
  REVIEW/HOLD before a human looks. Only fires with ≥5 adjudications; cold/healthy
  classes untouched.
- ☑ **Bet #3 (trust layer):** `tools/proof_repro.py` attaches a deterministic,
  one-click reproduction command (+ the exact signal to look for) to EVERY finding
  via `add_finding`. A triager pastes one line, sees the signal, trusts it in 30s —
  the opposite of volume-flooding. Verified LIVE: the generated repros actually
  reproduce the planted SQLi/XSS/SSTI/LFI/CORS against the lab
  (`tests/test_proof_repro.py` — 4 shape + 5 live).
- ☑ **1.3** `hypo-gen` reorders hypotheses by learned EV of their attack class and
  annotates each with `ev_prior`.
  - Verified (`tests/test_outcome_loop.py`): rejected-heavy class → `hold` bias +
    low p_accept; accepted class ranks higher by EV; sync is idempotent; CLI works.

---

## Phase 2 — Distributed local hunt grid  (axis: Throughput / scale)
*Why third: the scale win at ~0 cost to us; the pieces (`hunt-fleet`,
`hunt-queue`, `hunt-worker`, `hunt-swarm`, agent↔cloud job schema) already exist.*

- ☑ **2.2 (local/shared-storage grid)** Already built: `hunt-queue.py` (sqlite,
  WAL, atomic single-statement claim), `hunt-worker.py` (pull loop), `hunt-fleet.py`
  (fan out N workers sharing one bounded LLM slot pool). Workers on other
  machines work the same queue by pointing at a shared `HUNTR_FLEET_DB`.
  - Verified (`tests/test_fleet_queue.py`): 24 jobs × 8 concurrent workers → every
    job claimed exactly once, none double-assigned, queue drains clean.
- ☐ **2.1 (cloud dispatch) — DECISION NEEDED.** Wiring the cloud control plane
  (`/v1/jobs` dispatch in `cloud/app/`) to hand partitioned coverage-ledger cells
  to opt-in agents needs a running FastAPI + Postgres + a deploy target. That's
  an infrastructure decision (where it runs, who pays, auth model), not something
  to build blind. Blocked pending that call.

---

## Phase 3 — Autonomy with an audit trail  (axis: Autonomy)
*Why fourth: needs robustness (0) and the grid (2). Beat XBOW not by matching
autonomy but by making it trustworthy — unattended, but human-gated at submit,
and fully replayable.*

- ☑ **3.1** End-to-end unattended loop — **live-verified against the planted-vuln
  lab** (`bench/labs.py` via `hunt-bench.py`). Deterministic mode
  (`HUNT_NO_LLM=1`, new) completes unattended with **recall 0.958 (23/24), proof
  0.87, ev-recall 0.65, 0 false positives** — reproducible, no account needed.
  (Bet #1: the "cover EVERY applicable cell" top-up — a degraded/no-LLM plan can no
  longer skip whole classes like cors/ssti — lifted deterministic recall 0.417 →
  0.958.) The full LLM loop adds chained/LLM-guided depth on top.
- ☑ **3.2** Self-healing / resumable: pauses on rate-limit (`status: paused`),
  `--resume` reuses mapped surface + findings + coverage cells (confirmed in code).
- ☑ **3.3 (human gate + audit trail)** Never auto-submits — hard-triage grades
  each finding `submit`/`lead`/`info` for a human; the engine never POSTs. Every
  run leaves `run.json` (findings + coverage ledger) + `run.log` as the audit trail.
  - Locked by `tests/test_autonomous_loop.py` (`make verify-hunt`): asserts the
    loop completes unattended, finds+proves ≥3 core bug classes, 0 FP, never
    auto-submits, leaves an audit trail. (Gated behind `HUNT_RUN_SLOW=1` — it runs
    the full engine + external scanners, so it's on-demand, not in the fast gate.)

**New capability this phase:** `HUNT_NO_LLM` / `--no-llm` deterministic-only mode —
skips every LLM phase, runs the 0-token scanners + oracles + triage to completion.
Fast, offline, needs no Claude account, and makes autonomy reproducibly verifiable.

---

## Phase 4 — Exploitation depth  (axis: Exploitation depth / sophistication)
*Claude-native chaining + logic bugs = where an LLM out-thinks a benchmark scanner.*

- ☑ **4.1** Automatic capability chaining: new `tools/capability_edges.py` maps
  confirmed findings → capability edges; `capability-graph.py --from-findings`
  composes them and `analyze()` finds the chain by reachability.
  **Bet #2:** wired into the engine deterministically — `phase_chain` now runs in
  `HUNT_NO_LLM` (the LLM only enriches near-miss *strategy*), so confirmed findings
  auto-compose into escalated-severity chains with no account. Verified on real
  run findings: 103 findings → 101 edges reaching `account-takeover` + `cloud-role`
  (both CRITICAL). Locked by `tests/test_chain_depth.py` (5). This is the $-recall
  lever — one proven chain to ATO outranks many lows.
  - Verified (`tests/test_capability_chain.py`): 3 independent findings compose
    into one proven CRITICAL chain (userA→userB_token→admin_capability→all_tenants)
    that no single finding represents.
- ☑ **4.2** PoC-escalation ladder: satisfied by `analyze()`'s NEAR-MISS +
  `best_next` — when the goal is one unproven edge away it names the single
  highest-leverage edge to prove next.
  - Verified: dropping the last proven edge turns the chain into a near-miss and
    surfaces the exact next edge (`best_next.to == all_tenants`).
- ☑ **4.3** Business-logic exploitation proven end-to-end against a live target.
  - Verified (`tests/test_logic_bugs.py`): `mass-assign.py` CONFIRMS privesc on
    the mock's mass-assignable `/user/update` (fields stick, observed on GET) and
    confirms nothing on the allowlisted `/strict/update`.

---

## Phase 5 — Authenticated browser exploitation  (axis: Browser-native)
*Local + user creds reaches authed flows a cloud tool can't safely hold.*

- ☐ **5.1** `agent-browser`/`exec-cdp` as a first-class authenticated DOM driver
  (session, clicks, DOM-XSS/postMessage/CSWSH proven live + evidence capture).
- ☐ **5.2** Attack the real client surface from the live bundle
  (`js-api-harvest`, `js-diff`).
  - Verify: DOM-XSS proven end-to-end in a headless authed session with
    screenshot+HAR evidence.

---

## Phase 6 — Local-first compliance / enterprise tier  (axis: Compliance / enterprise fit)
*Turn local-first into the pitch XBOW structurally can't match: self-host/air-gap.*

- ☐ **6.1** Package scope-guard + rate-governor + audit trail as auditable
  authorization & blast-radius controls (recorded target authorization).
- ☐ **6.2** Enterprise checklist: SSO, RBAC, audit export, SOC2 path.
- ☐ **6.3** Self-hosted / air-gapped brain tier (the thing XBOW's cloud-only
  model can't offer).
  - Verify: a self-hosted brain runs a full hunt with no outbound calls; audit
    export produces a complete authorization + action log.

---

## Bet #4 — the money-weighted scoreboard (reframe the leaderboard)
*XBOW's brand is one volume leaderboard. Beat it with a better, reproducible one:
score PROVEN, high-$ findings; penalize junk submissions; measure on ground truth.*

- ☑ `hunt-bench.py` now emits a **money-weighted, FP-penalized** scorecard:
  `$-recall` (Σ bounty-$ of PROVEN found bugs ÷ Σ possible), `fp_rate` (would-be junk
  submissions ÷ all submits), and the **HUNTR Score** = `$-recall × proof_rate ×
  (1 − fp_rate)` ∈ [0,1] — volume can't game it (unproven/FP findings add nothing).
- **Verified on the planted-vuln lab (deterministic, no account):**
  **$-recall 0.951** ($40,900 / $43,000 proven impact), **fp_rate 0.0**,
  **HUNTR Score 0.827.** Locked by `tests/test_bench_score.py` (3).
- This is the reproducible, honest, publishable number HUNTR wins on — one a
  cloud black box can't credibly match.

## Verification discipline (applies to every step)
No step is "done" until its verify line passes. Phase 0 delivers `make verify`
(unit tests + stress battery + Playwright); later phases add their checks to it.
The knowledge graph (`/graphify`) is refreshed after each phase so the god-nodes
and community structure stay an honest map of what was actually built.
