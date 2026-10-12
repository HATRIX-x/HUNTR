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
- ☑ **1.3** `hypo-gen` reorders hypotheses by learned EV of their attack class and
  annotates each with `ev_prior`.
  - Verified (`tests/test_outcome_loop.py`): rejected-heavy class → `hold` bias +
    low p_accept; accepted class ranks higher by EV; sync is idempotent; CLI works.

---

## Phase 2 — Distributed local hunt grid  (axis: Throughput / scale)
*Why third: the scale win at ~0 cost to us; the pieces (`hunt-fleet`,
`hunt-queue`, `hunt-worker`, `hunt-swarm`, agent↔cloud job schema) already exist.*

- ☐ **2.1** Cloud brain dispatches partitioned work (coverage-ledger cells) to
  opt-in local agents that pull jobs.
- ☐ **2.2** Workers execute in parallel across targets×classes; results stream
  back as metadata (raw stays local).
  - Verify: N workers drain a queue of M jobs with no double-work and no
    workspace clobber (idempotent start already landed); throughput scales ~linearly.

---

## Phase 3 — Autonomy with an audit trail  (axis: Autonomy)
*Why fourth: needs robustness (0) and the grid (2). Beat XBOW not by matching
autonomy but by making it trustworthy — unattended, but human-gated at submit,
and fully replayable.*

- ☐ **3.1** End-to-end unattended loop: recon→surface→hypothesize→exploit→verify
  →draft runs with no human until the SUBMIT gate.
- ☐ **3.2** Self-healing: survive crash/rate-limit/timeout and resume from the
  coverage ledger (`log-doctor` + stalled-run detection already exist).
- ☐ **3.3** Every autonomous decision logged + replayable (the differentiator vs
  XBOW's black box).
  - Verify: kill an autonomous run mid-phase; it resumes and completes; the full
    decision log replays deterministically.

---

## Phase 4 — Exploitation depth  (axis: Exploitation depth / sophistication)
*Claude-native chaining + logic bugs = where an LLM out-thinks a benchmark scanner.*

- ☐ **4.1** Capability-graph chaining: compose confirmed primitives into
  higher-severity chains automatically (IDOR+mass-assign→cross-tenant ATO).
- ☐ **4.2** PoC-escalation ladder per finding: detect→confirm→escalate-to-max-
  impact→auto-repro.
- ☐ **4.3** Double down on `hunt-invariant-mining` (business-logic class XBOW is
  weakest on).
  - Verify: a seeded multi-primitive target yields a chained finding no single
    probe produces; invariant miner flags a planted logic bug.

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

## Verification discipline (applies to every step)
No step is "done" until its verify line passes. Phase 0 delivers `make verify`
(unit tests + stress battery + Playwright); later phases add their checks to it.
The knowledge graph (`/graphify`) is refreshed after each phase so the god-nodes
and community structure stay an honest map of what was actually built.
