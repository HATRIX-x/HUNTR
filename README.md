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
