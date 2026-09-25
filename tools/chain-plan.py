#!/usr/bin/env python3
"""
chain-plan — goal-driven exploitation planning on top of the capability graph.

capability-graph.py answers "what's reachable?". chain-plan answers "how do I reach a WIN, and what's
the ONE primitive to hunt next to get there?" — it fixes high-value GOALS (account takeover, RCE, PII
dump, fund theft, admin) and, from your PROVEN primitives in capabilities.tsv, reports for each goal:
  ACHIEVED      a proven path already reaches it (report at full impact)
  ONE AWAY      one unproven edge stands between you and it → the exact next primitive + which
                hunt-<class> yields it + where (endpoints pulled from signals.json)
  BLOCKED       no path yet → the missing capability + the classes that typically produce it
Goals are ranked by severity × your paid history (outcome EV). This is deliberate escalation:
turn two mediums into a critical instead of hoping.

Edges file (same as capability-graph): ./.hunt/capabilities.tsv
  from   primitive   to   status(proven|partial|unproven)   impact(-|c/h/m/l)   evidence

Usage:  chain-plan.py [--file ./.hunt/capabilities.tsv] [--have userA-token] [--goal ato,rce]
Exit: 0 a goal is ACHIEVED · 1 only ONE-AWAY/BLOCKED goals.
"""
import sys, os, re, json, importlib.util
from pathlib import Path
from collections import deque, defaultdict

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
FILE = Path(sys.argv[sys.argv.index("--file") + 1]) if "--file" in sys.argv else HUNT / "capabilities.tsv"
SEVNAME = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW"}
SEVRANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# goal → (severity, node-name patterns that satisfy it, capability needed if blocked, classes that yield it)
GOALS = {
    "ato":   ("critical", r"(token|session|cred|password|reset|impersonat|victim|account.?takeover|admin_session)",
              "a stolen/forged auth token or a password-reset primitive",
              ["jwt", "authbypass", "oauth", "xss", "session", "idor"]),
    "rce":   ("critical", r"(rce|exec|shell|command|deserial|code.?exec|webshell)",
              "code execution (upload+exec, deserialization, SSTI, or stacked SQLi)",
              ["rce", "deserialization", "ssti", "fileupload", "sqli"]),
    "pii":   ("high", r"(other.?user|all.?(user|tenant|record)|pii|dump|db_read|mass.?data|enumerat)",
              "cross-user data read + enumeration at scale",
              ["idor", "sqli", "authz", "nosqli"]),
    "funds": ("high", r"(balance|fund|payout|withdraw|double.?spend|money|credit|refund)",
              "a value/balance-changing primitive",
              ["race", "logic"]),
    "admin": ("high", r"(admin|superuser|all_tenants|manage|privileg|global.?config)",
              "admin/privileged function access",
              ["bfla", "authz", "authbypass"]),
    "tenant": ("high", r"(cross.?tenant|other.?tenant|all_tenants|org.?b)",
               "cross-tenant access",
               ["authz", "idor"]),
}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def load_edges():
    if not FILE.exists():
        sys.exit(f"[chain-plan] no {FILE}. Add proven primitives as edges first (see capability-graph.py --file).")
    edges = []
    for ln in FILE.read_text().splitlines():
        s = ln.rstrip()
        if not s.strip() or s.strip().startswith("#"):
            continue
        c = s.split("\t")
        if len(c) < 3:
            continue
        edges.append({"frm": c[0].strip(), "prim": c[1].strip(), "to": c[2].strip(),
                      "status": (c[3].strip().lower() if len(c) > 3 else "proven")})
    return edges


def bfs(edges, starts, allow):
    adj = defaultdict(list)
    for e in edges:
        if e["status"] in allow:
            adj[e["frm"]].append(e)
    seen, par, q = set(starts), {}, deque(starts)
    while q:
        n = q.popleft()
        for e in adj[n]:
            if e["to"] not in seen:
                seen.add(e["to"]); par[e["to"]] = e; q.append(e["to"])
    return seen, par


def path_to(node, par):
    ch = []
    while node in par:
        ch.append(par[node]); node = par[node]["frm"]
    return list(reversed(ch))


def render(chain):
    if not chain:
        return "     (already held)"
    line = "     " + chain[0]["frm"]
    for e in chain:
        line += f"  {'──▶' if e['status']=='proven' else '╌╌▶'}[{e['prim']}]  {e['to']}"
    return line


def outcome_ev():
    p = Path(__file__).with_name("outcome-check.py")
    if not p.exists():
        return {}
    spec = importlib.util.spec_from_file_location("outcome_check", p)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m.all_classes_with_priors(m.score(m.load(m.GLOBAL)))


def endpoints_for(cls, signals):
    """suggest where to hunt this class from recon signals."""
    eps = signals.get("endpoints", []) + [f"?{p}=" for p in signals.get("fields", [])]
    hints = {"idor": ["{id}", "/orders", "/users", "/profile", "/account"],
             "sqli": ["search", "q", "filter", "sort"], "ssrf": ["url", "fetch", "webhook", "callback"],
             "bfla": ["admin", "internal", "manage"], "authz": ["settings", "config", "internal", "org"],
             "race": ["transfer", "redeem", "coupon", "withdraw", "topup"], "fileupload": ["upload", "file", "avatar"],
             "jwt": ["token", "auth"], "oauth": ["authorize", "redirect", "oauth"], "session": ["auth", "logout"]}
    kws = hints.get(cls, [])
    hit = [e for e in eps if any(k in e.lower() for k in kws)]
    return hit[:3]


def main():
    edges = load_edges()
    starts = {"anon"} | (set(arg("--have", "").split(",")) if arg("--have") else set())
    want = set((arg("--goal") or "").split(",")) if arg("--goal") else set(GOALS)
    signals = {}
    if (HUNT / "signals.json").exists():
        try:
            signals = json.loads((HUNT / "signals.json").read_text())
        except Exception:
            pass
    ev = outcome_ev()

    proven_reach, proven_par = bfs(edges, starts, {"proven"})
    all_reach, all_par = bfs(edges, starts, {"proven", "partial", "unproven"})
    nodes = {e["frm"] for e in edges} | {e["to"] for e in edges}

    def matches(pattern, pool):
        rx = re.compile(pattern, re.I)
        return [n for n in pool if rx.search(n)]

    results = []
    for g in want:
        if g not in GOALS:
            continue
        sev, pat, missing_cap, classes = GOALS[g]
        best_ev = max((ev.get(c, {}).get("ev", 0) for c in classes), default=0)
        proven_hit = matches(pat, proven_reach - starts)
        near_hit = matches(pat, all_reach - proven_reach)
        if proven_hit:
            state = "ACHIEVED"
        elif near_hit:
            state = "ONE-AWAY"
        elif matches(pat, nodes):
            state = "PARTIAL-GRAPH"  # goal node exists but not reachable at all
        else:
            state = "BLOCKED"
        results.append((SEVRANK[sev], -best_ev, g, sev, state, proven_hit, near_hit,
                        missing_cap, classes, best_ev))
    results.sort()

    print("\n══ GOAL-DRIVEN PLAN ═══════════════════════════════════════")
    print(f"  proven capabilities: {len(proven_reach - starts)} · graph nodes: {len(nodes)} · edges: {len(edges)}\n")
    any_achieved = False
    for _, _, g, sev, state, phit, nhit, missing_cap, classes, gev in results:
        head = f"  [{SEVNAME[sev[0].upper().lower()] if False else sev.upper()}] {g.upper()}  (EV≈${gev:.0f})"
        if state == "ACHIEVED":
            any_achieved = True
            print(f"{head}  ✓ ACHIEVED")
            print(render(path_to(phit[0], proven_par)))
            print("     → report this chain at full impact; run adversarial-verify.py to lock severity.\n")
        elif state == "ONE-AWAY":
            node = nhit[0]
            ch = path_to(node, all_par)
            miss = [e for e in ch if e["status"] != "proven"]
            print(f"{head}  ◐ ONE-AWAY — {len(miss)} edge(s) to prove")
            print(render(ch))
            for e in miss:
                print(f"       ⇒ prove [{e['prim']}]  {e['frm']} → {e['to']}  ({e['status']})")
            print()
        else:
            print(f"{head}  ✗ {state}")
            print(f"       missing: {missing_cap}")
            print(f"       hunt to unlock: {', '.join('hunt-'+c for c in classes[:4])}")
            for c in classes[:2]:
                where = endpoints_for(c, signals)
                if where:
                    print(f"         · {c}: try {', '.join(where)}")
            print()
    if not results:
        print("  (no goals selected/known)\n")
    print("  ➜ Prioritise the highest-severity ONE-AWAY goal: proving one primitive escalates the whole chain.\n")
    sys.exit(0 if any_achieved else 1)


if __name__ == "__main__":
    main()
