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
