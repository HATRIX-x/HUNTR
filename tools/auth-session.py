#!/usr/bin/env python3
"""
auth-session — manage testing identities and keep their tokens fresh. Stale
sessions are the #1 friction in authenticated hunting; this decodes JWT expiry
and can refresh via an OAuth refresh_token grant, in place.

Identity store (shared with exec-http):  <HUNT_DIR>/identities.json
  { "admin": { "authorization": "Bearer eyJ…", "cookie": "sid=…",
               "headers": {"X-CSRF": "…"},
               "refresh": { "token_url": "https://id/oauth/token",
                            "refresh_token": "…", "client_id": "…",
                            "client_secret": "…"(optional) } } }

Actions:
  --status [--name N]                 decode each JWT, show valid / expiring / expired
  --set --name N [--authorization .. --cookie .. --header 'K: V' ..]
  --set-refresh --name N --token-url U --refresh-token R [--client-id .. --client-secret ..]
  --refresh --name N                  do the refresh grant, update authorization
  --refresh-all [--skew 120]          refresh every identity whose JWT expires within skew s

Usage:
  auth-session.py --status --json
Exit: 0 ok · 1 a refresh failed.
"""
import sys, os, json, time, base64, ssl
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlencode

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))
IDS = HUNT / "identities.json"


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def args_multi(n):
    return [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == n and i + 1 < len(sys.argv)]
def flag(n):
    return n in sys.argv


def load():
    if IDS.exists():
        try:
            return json.loads(IDS.read_text())
        except Exception:
            return {}
    return {}


def save(d):
    HUNT.mkdir(parents=True, exist_ok=True)
    IDS.write_text(json.dumps(d, indent=2))


def jwt_claims(token):
    if not token:
        return None
    t = token.split(" ", 1)[-1] if " " in token else token
    parts = t.split(".")
    if len(parts) < 2:
        return None
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(pad))
    except Exception:
        return None


def token_status(rec, skew=0):
    claims = jwt_claims(rec.get("authorization", ""))
    if not claims:
        return {"kind": "opaque", "state": "unknown"}
    exp = claims.get("exp")
    if not exp:
        return {"kind": "jwt", "state": "no-exp", "sub": claims.get("sub")}
    now = time.time()
    remaining = int(exp - now)
    state = "expired" if remaining <= 0 else ("expiring" if remaining <= max(1, skew) else "valid")
    return {"kind": "jwt", "state": state, "exp": exp,
            "remaining_s": remaining, "sub": claims.get("sub")}


def do_refresh(rec):
    r = rec.get("refresh") or {}
    if not r.get("token_url") or not r.get("refresh_token"):
        return False, "no refresh config"
    form = {"grant_type": "refresh_token", "refresh_token": r["refresh_token"]}
    if r.get("client_id"):
        form["client_id"] = r["client_id"]
    if r.get("client_secret"):
        form["client_secret"] = r["client_secret"]
    req = Request(r["token_url"], data=urlencode(form).encode(),
                  headers={"Content-Type": "application/x-www-form-urlencoded",
                           "Accept": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=20, context=ssl.create_default_context()) as resp:
            data = json.loads(resp.read())
    except Exception as ex:
        return False, f"{type(ex).__name__}: {str(ex)[:150]}"
    at = data.get("access_token")
    if not at:
        return False, f"no access_token in response: {json.dumps(data)[:150]}"
    ttype = data.get("token_type", "Bearer")
    rec["authorization"] = f"{ttype} {at}" if " " not in ttype else at
    if data.get("refresh_token"):
        rec["refresh"]["refresh_token"] = data["refresh_token"]
    return True, "refreshed"


def main():
    ids = load()
    name = arg("--name")

    if flag("--set"):
        if not name:
            print("--name required"); sys.exit(1)
        rec = ids.setdefault(name, {})
        if arg("--authorization"): rec["authorization"] = arg("--authorization")
        if arg("--cookie"): rec["cookie"] = arg("--cookie")
        hdrs = rec.setdefault("headers", {})
        for h in args_multi("--header"):
            if ":" in h:
                k, v = h.split(":", 1); hdrs[k.strip()] = v.strip()
        save(ids)
        print(json.dumps({"ok": True, "name": name}) if flag("--json") else f"set {name}")
        sys.exit(0)

    if flag("--set-refresh"):
        if not name:
            print("--name required"); sys.exit(1)
        rec = ids.setdefault(name, {})
        rec["refresh"] = {
            "token_url": arg("--token-url", ""),
            "refresh_token": arg("--refresh-token", ""),
            "client_id": arg("--client-id", ""),
            "client_secret": arg("--client-secret", ""),
        }
        save(ids)
        print(json.dumps({"ok": True, "name": name, "refresh": "configured"}) if flag("--json")
              else f"refresh configured for {name}")
        sys.exit(0)

    if flag("--refresh") or flag("--refresh-all"):
        skew = int(arg("--skew", "120"))
        targets = [name] if (flag("--refresh") and name) else list(ids.keys())
        results, any_fail = [], False
        for nm in targets:
            rec = ids.get(nm)
            if not rec:
                results.append({"name": nm, "ok": False, "msg": "no such identity"}); any_fail = True; continue
            if flag("--refresh-all"):
                st = token_status(rec, skew)
                if st["state"] not in ("expired", "expiring", "no-exp", "unknown"):
                    results.append({"name": nm, "ok": True, "msg": f"skip ({st['state']})"}); continue
            ok, msg = do_refresh(rec)
            any_fail = any_fail or not ok
            results.append({"name": nm, "ok": ok, "msg": msg})
        save(ids)
        out = {"ok": not any_fail, "results": results}
        print(json.dumps(out) if flag("--json")
              else "\n".join(f"  {r['name']:<14} {'✓' if r['ok'] else '✗'} {r['msg']}" for r in results))
        sys.exit(1 if any_fail else 0)

    # default: status
    skew = int(arg("--skew", "120"))
    rows = []
    for nm, rec in ids.items():
        if name and nm != name:
            continue
        st = token_status(rec, skew)
        rows.append({"name": nm, **st,
                     "has_cookie": bool(rec.get("cookie")),
                     "can_refresh": bool((rec.get("refresh") or {}).get("refresh_token"))})
    out = {"ok": True, "count": len(rows), "identities": rows}
    if flag("--json"):
        print(json.dumps(out)); sys.exit(0)

    print(f"\n== auth-session · {len(rows)} identities ==")
    for r in rows:
        extra = f"exp in {r['remaining_s']}s" if r.get("remaining_s") is not None else r.get("kind", "")
        print(f"  {r['name']:<14} [{r['state']:<8}] {extra}"
              + ("  ↻refreshable" if r["can_refresh"] else ""))
    if not rows:
        print("  (no identities — add one with --set)")
    sys.exit(0)


if __name__ == "__main__":
    main()
