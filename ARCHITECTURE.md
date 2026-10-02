# HUNTR — Hybrid SaaS Architecture

Build-ready blueprint for HUNTR as **local agent + cloud control plane + web dashboard**.

The rule that drives every decision: **the attack always originates from the user's
machine (their IP, their authorized identity); the valuable brain and aggregated
data live in the cloud where they're protected.** Target credentials and raw
evidence never leave the agent.

```
┌── AGENT (user's machine) ──┐   HTTPS/WSS   ┌── CLOUD (your servers) ──┐   ┌── WEB (browser) ──┐
│ • the ~80 tools (attack)   │◄────────────► │ • orchestration brain     │◄─►│ • dashboard        │
│ • user's IP + session      │  jobs+results │ • LLM layer (metered)     │   │ • hunts / verdicts │
│ • raw evidence + tokens    │               │ • dedup corpus (moat)     │   │ • funnel metrics   │
│ • local API :8899          │               │ • findings index + billing│   │                    │
└────────────────────────────┘               └───────────────────────────┘   └────────────────────┘
       heavy + sensitive                         light + valuable + protected      a view only
```

---

## 1. Components & responsibilities

### Agent (local, ships to the user)
- Runs every probe/tool — attacks from the **user's IP and authenticated sessions**.
- Enforces `scope-guard` locally **before any request leaves the machine**.
- Holds and never uploads: target auth tokens, cookies, raw request/response evidence,
  the CDP browser hook, Burp/proxy access.
- Exposes the existing local API on `127.0.0.1:8899` (unchanged for local use).
- Adds a **sync client**: authenticates to cloud with an agent token, pulls jobs,
  returns finding metadata (not raw secrets).

### Cloud (control plane, your servers)
- **Auth & accounts**, agent registration, billing.
- **Orchestration brain**: decides the next hunt (`hypo-gen`, `chain-builder` run here),
  dispatches jobs to the agent.
- **LLM layer**: server-side model calls, metered — or proxied to the user's own key.
- **Storage**: findings index, funnel metrics, reports, and the **anonymized dedup corpus**
  (the moat).
- **Dashboard API** + serves the web app. Optional server-side **watchtower**
  (`scope-radar`, `js-diff`) for passive recon that doesn't need the user's IP.

### Web (browser)
- The dashboard (evolves from `huntr-ui.html`). Reads the cloud API; can also talk to a
  running local agent on `127.0.0.1:8899` for live/local actions.

### Map from today's code
| Today | Goes to | Notes |
|---|---|---|
| ~80 tools + `huntrlib` | **Agent** | unchanged — already run local |
| `huntr-server.py` | **Agent** local API + new cloud-sync client | |
| `huntr-ui.html` | **Web** (served by cloud) | talks to cloud + local agent |
| `hypo-gen`, `chain-builder`, `report-draft` | **Cloud** | LLM billed server-side |
| `funnel`, `disclosed-index`, dedup corpus | **Cloud** | aggregation = moat |
| `finding-pipeline` | **Hybrid** | verify/evidence local · dedup/draft/verdict cloud |

---

## 2. What runs / stores where

| Data | Location | Why |
|---|---|---|
| Raw request/response evidence, screenshots | **Agent (local)** | heavy + sensitive; no cost to you |
| Target auth tokens / cookies / sessions | **Agent only — never uploaded** | legal + security liability |
| Findings index (class, endpoint, severity, status) | **Cloud** | text; powers dashboard + sync |
| Funnel events (flagged→accepted, amounts) | **Cloud** | measure + display |
| Dedup corpus / disclosed reports (**anonymized**) | **Cloud** | the moat, must be central |
| Reports (markdown) | **Cloud object store** (opt-in) | shareable, but user-controlled |
| Brain code (AI, chaining, scoring) | **Cloud only** | protected even if agent is reversed |

---

## 3. Data model (Postgres)

```sql
users            (id, email, created_at, plan, stripe_customer_id)
agents           (id, user_id, name, token_hash, os, version, last_seen)
targets          (id, user_id, program, platform, base_url,
                  scope_json, authorized_at, created_at)
jobs             (id, user_id, agent_id, target_id, task_json,
                  status, created_at, started_at, finished_at, error)
                  -- status: queued|dispatched|running|done|error
findings         (id, user_id, target_id, job_id, class, endpoint,
                  severity, status, verdict, title, dup_prob,
                  amount, evidence_local_ref, report_id,
                  created_at, updated_at)
                  -- status: flagged|confirmed|submitted|accepted|dupe|rejected|paid
                  -- evidence_local_ref = pointer into the agent; NO raw secrets here
funnel_events    (id, user_id, target_id, finding_id, stage, amount, ts)  -- append-only
corpus           (id, class, endpoint_template, weakness, source,
                  signature, created_at)                                   -- anonymized
reports          (id, finding_id, template, markdown_ref, score, word_count)
subscriptions    (user_id, stripe_sub_id, tier, status, renews_at)
notifications    (id, user_id, type, payload_json, created_at, sent_at)
```

Rules:
- `findings` and `funnel_events` mirror the existing tool output exactly (`class`,
  `endpoint`, `status` stages already match `funnel.py` / `dup-score.py`).
- `evidence_local_ref` is just the agent's `.hunt/evidence/<id>` key — the bytes stay local.
- `corpus` rows carry **no target identity** — only class + endpoint template + signature.

---

## 4. Job schema (the agent↔cloud contract)

**Dispatch — cloud → agent**
```json
{
  "job_id": "job_01H...",
  "target": { "id": "t_01H...", "base_url": "https://api.acme.com", "scope": ["*.acme.com"] },
  "task":   { "tool": "mass-assign",
              "args": { "url": "https://api.acme.com/user/update", "method": "PUT",
                        "id_field": "id", "id": "victim-1",
                        "verify_get": "https://api.acme.com/user/{id}" } },
  "identity": "session-a",
  "budget":   { "max_requests": 50 }
}
```

**Result — agent → cloud** (metadata only; raw stays local)
```json
{
  "job_id": "job_01H...",
  "status": "done",
  "tool": "mass-assign",
  "findings": [
    { "id": "F1", "class": "idor", "endpoint": "/user/{id}", "severity": "critical",
      "impact": "ATO", "reflected": true, "evidence_local_ref": "F1" }
  ],
  "stats": { "confirmed": 3, "flagged": 5 },
  "error": null
}
```

The agent runs the tool with `--json` (unchanged), strips secrets, and posts this. The
cloud then runs the brain (`finding-pipeline` dedup/verdict/draft) and updates `findings`.

---

## 5. Cloud API (REST + one WS)

```
# auth & agent lifecycle
POST /v1/auth/signup                 → { user, session }
POST /v1/auth/login                  → { session }
POST /v1/agents/register             → { agent_id, agent_token }     (bind to user)
WS   /v1/agent/connect               ← jobs stream ; → results, heartbeat
   (fallback) GET /v1/agent/jobs     (long-poll)
              POST /v1/agent/jobs/{id}/result

# targets (authorization is recorded here)
POST /v1/targets                     { program, platform, base_url, scope } → target
GET  /v1/targets

# hunting
POST /v1/hunt                        { target_id, plan? } → queues jobs
GET  /v1/jobs?target_id=             → job list/status
POST /v1/findings/{id}/pipeline      → run verify→dedup→verdict→draft (brain)
POST /v1/reports/{finding_id}/draft  → report-draft (LLM, metered)

# dashboard reads
GET  /v1/findings?target_id=&status= → findings index
GET  /v1/findings/{id}
GET  /v1/funnel/stats?target_id=     → FP rate / acceptance / unique / paid
GET  /v1/funnel/events

# billing & ops
POST /v1/billing/checkout            → Stripe session
POST /v1/billing/webhook             ← Stripe
GET  /v1/notifications
```

Agent endpoints require the **agent token**; dashboard endpoints require the **user session**.

---

## 6. Security & authorization (non-negotiable)

- **Target tokens/cookies never leave the agent.** The cloud stores only metadata +
  `evidence_local_ref` pointers.
- **Attacks originate on the agent** (user IP/identity), never from cloud infrastructure.
- The agent runs `scope-guard` locally and refuses out-of-scope **before** any request;
  the cloud records an **authorization consent** per `target` (`authorized_at`, scope).
- `corpus` uploads are **anonymized** — class + endpoint template + signature only, no host.
- Agent token is stored hashed; all transport TLS; per-user rate/egress budget enforced by
  `rate-governor` on the agent.

---

## 7. LLM & cost model

- LLM calls (`hypo-gen`, `chain-builder`, `report-draft`) run **server-side**, either
  metered (billed to the user with a margin) or proxied to the user's own key (zero COGS).
- Heavy scan compute runs on the **agent** — no server cost.
- Cloud is orchestration + text storage: a small VPS + Postgres + object store serves
  many users; marginal cost per user ≈ storage pennies + their LLM usage.

---

## 8. Build phases

| Phase | Deliverable | Reuses |
|---|---|---|
| **1 — thin cloud** | accounts + `POST /agent/jobs/{id}/result` + findings/funnel storage + dashboard reads. Agent still does all hunting; cloud = sync + dashboard + auth. | `huntr-ui.html`, `funnel.py`, findings shapes |
| **2 — brain up** | server-side `finding-pipeline` (dedup/verdict/draft) + LLM metering + Stripe billing | `hypo-gen`, `chain-builder`, `report-draft`, `dup-score` |
| **3 — watchtower** | server-side `scope-radar` + `js-diff` monitoring → notifications; teams/collab | `scope-radar`, `js-diff`, `notify` |

**Phase 1 is the smallest real SaaS** and reuses almost everything you have.

---

## 9. Tech stack

- **Agent**: Python (existing engine), packaged via `pipx` / one-line installer; local API stays.
- **Cloud**: **FastAPI** (reuse tool code + `huntrlib`), **Postgres**, **S3/R2** object store.
- **Web**: `huntr-ui.html` now → SPA later.
- **Auth**: Clerk/Auth0 or email+token. **Billing**: Stripe. **LLM**: Anthropic API server-side or user key.
- **Host**: Fly.io / Railway / small VPS.
