# HATRIX

Local bug bounty hunting engine. Runs at `http://127.0.0.1:8899`.

## Start

```bash
python3 tools/huntr-server.py
# open http://127.0.0.1:8899
```

## Tools

### Tier 1 — Static analysis
| Tool | Purpose |
|------|---------|
| `js-diff.py` | JS bundle snapshot + diff (new endpoints, secrets) |
| `graphql-map.py` | GraphQL introspection → IDOR/auth/upload map |
| `report-score.py` | Report quality scorer 0–100 across 6 dimensions |
| `github-recon.py` | GitHub org/repo secret + CI/CD scanner |
| `nuclei-run.py` | Nuclei template runner → HUNTR finding format |

### Tier 2 — Active probing
| Tool | Purpose |
|------|---------|
| `subdomain-enum.py` | Passive (crt.sh, hackertarget, alienvault) + brute |
| `cors-test.py` | 9 CORS misconfig vectors incl. credentials:true |
| `jwt-test.py` | alg:none, weak secret, RS→HS confusion, kid traversal, jku SSRF |
| `param-fuzz.py` | 400-param differential sweep + IDOR prober |
| `scope-radar.py` | Program scope/reward change monitor (H1/BC/YWH/ING) |

### Tier 3 — Exploit probes
| Tool | Purpose |
|------|---------|
| `ssrf-probe.py` | SSRF: metadata endpoints, bypass variants, blind callback |
| `race-fire.py` | Race condition: gate-release × N threads, TOCTOU detection |
| `ssti-probe.py` | SSTI/CSTI: 14 engine polyglots, auto-escalates to RCE fingerprint |
| `takeover-check.py` | Subdomain takeover: 45-service fingerprint DB |
| `open-redirect.py` | 15 bypass vectors + OAuth token-theft chain builder |

### Tier 4 — Business logic
| Tool | Purpose |
|------|---------|
| `idor-chain.py` | Cross-account replay IDOR + numeric enum + sequential-GUID + hashed-id bypass |
| `auth-bypass.py` | 403/401 bypass matrix: header strip, X-Original-URL, verb swap, path/case/ext mutation |
| `rate-limit.py` | Throttle detection + bypass (X-Forwarded-For / null-Origin / UA / path-case) |
| `oauth-probe.py` | redirect_uri, state/CSRF, implicit leak, PKCE downgrade, scope escalation, code reuse |
| `logic-fuzz.py` | Per-field JSON mutation: negatives, 2^31/2^63, type confusion, bool flip, array-wrap, dup key |
| `mass-assign.py` | Promote a write into a chain: probes `password`/`role`/`type`/`active`/`tenantId`… for mass-assignment → ATO / privesc / lockout / cross-tenant, confirmed by GET reflection |

### Tier 5 — LLM intelligence
| Tool | Purpose |
|------|---------|
| `hypo-gen.py` | Highest-ROI untested attack hypotheses + a ready HUNTR command each |
| `chain-builder.py` | Combine confirmed findings into higher-severity exploit chains |
| `report-draft.py` | Draft-only platform reports (H1 / YesWeHack / Bugcrowd / Intigriti) — never auto-submits |

Tier 5 tools call the Claude API over `urllib` and read `ANTHROPIC_API_KEY` from
the environment (or `--api-key`); they degrade gracefully when no key is set.

### Tier 6 — Evidence, integrations & regression
| Tool | Purpose |
|------|---------|
| `disclosed-index.py` | Pull publicly disclosed reports (H1 hacktivity + seed file) into the dedup corpus |
| `evidence-bundle.py` | Assemble request/response + curl repro + HAR + screenshot into a submit-ready zip |
| `rate-governor.py` | Global + per-program token-bucket traffic budget above every probe |
| `proxy-ingest.py` | Import Burp XML / HAR / URL list → endpoint inventory |
| `notify.py` | Push events to Slack / Discord / generic webhook |
| `auth-session.py` | Identity store + JWT expiry status + OAuth refresh_token grant |
| `ws-probe.py` | WebSocket: CSWSH, missing auth, origin reflection, graphql-ws subscriptions |
| `nuclei-gen.py` | Turn a confirmed finding into a reusable Nuclei YAML template |
| `retest.py` | Re-fire a stored finding to confirm still-vulnerable / fixed (retest bonus) |
| `funnel.py` | Log findings `flagged → confirmed → submitted → accepted` and compute the real false-positive / acceptance / unique rates |

### Capstone — triage pipeline
| Tool | Purpose |
|------|---------|
| `finding-pipeline.py` | One command per finding: verify (retest + adversarial-verify) → dedup-score → evidence-bundle → report-draft → **SUBMIT / REVIEW / HOLD**. Never auto-submits. |

`finding-pipeline.py` orchestrates the tools above, so a raw probe hit comes out as a
verified, deduped, evidence-backed, draft-ready decision. Exit: `0` SUBMIT · `1` REVIEW · `2` HOLD.

## Requirements

- Python 3.9+
- `nuclei` (optional, for nuclei-run.py)
- `dig` (optional, for takeover-check.py CNAME resolution)
- `trufflehog` / `gitleaks` (optional, for github-recon.py)

## Architecture

```
huntr-server.py   ← HTTP bridge at 127.0.0.1:8899
huntr-ui.html     ← premium UI (served by server)
huntr-bridge.js   ← injected at runtime; wires UI to API routes
tools/*.py        ← deterministic probes, all support --json
```

The server injects `huntr-bridge.js` into the UI at runtime. The bridge overrides
UI render functions to fire live engine calls instead of demo data.

All tools accept `--json` for structured output and are safe to pipe.

## Engineering

- **`tools/huntrlib.py`** — the shared core (arg parsing, one HTTP client with SSL /
  auth / timeout / size-cap / uniform error handling, the JSON envelope). New tools
  `import huntrlib as H` instead of re-implementing it, so a fix lands once.
- **`tests/`** — stdlib `unittest`, zero deps. A reusable in-process mock target
  (`tests/mock_target.py`) plus regression tests that lock in real bugs found in review
  (e.g. mass-assign's reflection false-positive). Run:

  ```bash
  python3 -m unittest discover -s tests -p "test_*.py"
  ```
- **CI** — `.github/workflows/ci.yml` byte-compiles every tool and runs the suite on
  each push and PR.

## Measuring detection quality

`funnel.py` turns "is it accurate?" into a number. Log each finding as it moves:

```bash
funnel.py --log --id F1 --target acme --tool mass-assign --class idor --stage flagged
funnel.py --log --id F1 --target acme --stage accepted --amount 500
funnel.py --stats --target acme          # false-positive rate, acceptance, unique, paid
```
False-positive rate = `rejected / (accepted + dupe + rejected)` — of everything a program
adjudicated, how much it deemed not-a-bug.
