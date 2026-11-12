#!/usr/bin/env python3
"""
creds-test — verify credentials actually authenticate against the target, before trusting
them for a hunt (and re-usable mid-hunt to sanity-check after a swap).

Answers the two questions an operator actually has when they hand HUNTR a cookie/token/header:
  1. "Is this even the right one — is it doing ANYTHING to the response?"
  2. "Did my session just expire / get revoked?"

Fires the SAME GET request twice, directly via curl — once with no credentials, once with the
supplied ones attached — and diffs status/length/redirect/login-page markers between the two. If
the Authorization value or cookie value looks like a JWT, decodes its `exp` claim without needing
the signing key (we only need to know what it CLAIMS, not verify the signature — the direct request
still sends the real probe, which is the actual proof).

Usage:
  creds-test.py --url https://api.acme.com/ \\
                 [--authorization "Bearer eyJ…"] [--cookie "sid=abc123"] \\
                 [--auth-header "X-FilesAPI-Auth: a249baf3…"]... [--ua "BugBounty-X"] [--json]

Verdicts:
  looks-authenticated      authed response differs from anon in a way consistent with being logged in
  no-visible-difference    authed and anon responses are indistinguishable — wrong cookie/header
                            name, or the target ignores it entirely
  authed-looks-logged-out  the AUTHED response itself contains login-page markers / redirects to login
  jwt-expired              the token's own `exp` claim has already passed — don't even bother sending it
  request-failed           the probe itself failed (DNS/network/timeout), not a credentials signal

Exit: 0 looks-authenticated · 1 no-visible-difference / authed-looks-logged-out · 2 jwt-expired / error.
"""
import sys, os, re, json, time, base64, subprocess

_LOGIN_MARKERS = re.compile(
    r"(log[\s-]?in|sign[\s-]?in|unauthoriz|authentication required|session (has )?expired|please log)",
    re.I,
)


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def flag(n):
    return n in sys.argv


def args_multi(n):
    a = sys.argv
    return [a[i + 1] for i, x in enumerate(a) if x == n and i + 1 < len(a)]


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


def fire(url, headers, ua=""):
    cmd = ["curl", "-sS", "-i", "--max-time", "25", "-X", "GET", url]
    for h in headers:
        cmd += ["-H", h]
    if ua:
        cmd += ["-A", ua]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout
    except Exception as e:
        return -1, "error: " + str(e)[:200]


def parse(resp):
    if not resp:
        return {"status": 0, "len": 0, "location": "", "login_marker": False}
    head, _, body = resp.partition("\r\n\r\n")
    if not body and "\n\n" in resp:
        head, _, body = resp.partition("\n\n")
    first = resp.split("\n", 1)[0]
    status = 0
    for tok in first.split():
        if tok.isdigit() and len(tok) == 3:
            status = int(tok)
            break
    loc = ""
    for line in head.splitlines():
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
            break
    return {"status": status, "len": len(body), "location": loc,
            "login_marker": bool(_LOGIN_MARKERS.search(body[:4000]))}


def main():
    url = arg("--url")
    if not url:
        print(__doc__)
        sys.exit(2)
    authz = arg("--authorization", "")
    cookie = arg("--cookie", "")
    # BUG FIX (2026-10-21): an operator pasting a cookie often pastes a raw Netscape cookie-jar
    # FILE (curl -c / browser "export cookies" format) rather than an actual Cookie-header string.
    # Sent verbatim, that's not valid cookie syntax — the probe silently runs anonymous and this
    # tool would then confidently report "no-visible-difference: wrong cookie" on a cookie that
    # was actually fine, just mis-shaped. Normalize before using it, same fix as hunt-run.py's
    # _creds() — see huntrlib.normalize_cookie's docstring.
    try:
        import huntrlib as H
        cookie = H.normalize_cookie(cookie)
    except Exception:
        pass
    ua = arg("--ua", "")
    ah_lines = args_multi("--auth-header")

    creds_headers = []
    if authz:
        creds_headers.append(f"Authorization: {authz}")
    if cookie:
        creds_headers.append(f"Cookie: {cookie}")
    for h in ah_lines:
        if ":" in h:
            creds_headers.append(h.strip())

    if not creds_headers:
        out = {"ok": False, "verdict": "no-creds-supplied", "error": "no credentials supplied"}
        print(json.dumps(out) if flag("--json") else "no credentials supplied")
        sys.exit(2)

    jwt = None
    claims = jwt_claims(authz) or jwt_claims(cookie)
    if claims:
        exp = claims.get("exp")
        if exp:
            remaining = int(exp - time.time())
            jwt = {"sub": claims.get("sub"), "exp": exp, "remaining_s": remaining,
                   "state": "expired" if remaining <= 0 else ("expiring" if remaining <= 300 else "valid")}
        else:
            jwt = {"sub": claims.get("sub"), "state": "no-exp"}

    rc_a, out_a = fire(url, [], ua)
    rc_b, out_b = fire(url, creds_headers, ua)

    if rc_a != 0 or rc_b != 0:
        result = {"ok": False, "verdict": "request-failed", "url": url}
        print(json.dumps(result) if flag("--json") else "request failed: " + url)
        sys.exit(2)

    anon = parse(out_a)
    authed = parse(out_b)

    if jwt and jwt["state"] == "expired":
        verdict = "jwt-expired"
    elif authed["login_marker"]:
        verdict = "authed-looks-logged-out"
    elif authed["status"] == anon["status"] and abs(authed["len"] - anon["len"]) <= 40 \
            and anon["login_marker"] == authed["login_marker"] and authed["location"] == anon["location"]:
        verdict = "no-visible-difference"
    else:
        verdict = "looks-authenticated"

    result = {"ok": verdict == "looks-authenticated", "verdict": verdict, "url": url,
              "anon": anon, "authed": authed, "jwt": jwt}

    if flag("--json"):
        print(json.dumps(result))
    else:
        print(f"[creds-test] {verdict}  ·  {url}")
        print(f"  anon  : status={anon['status']:<4} len={anon['len']:<6} login_marker={anon['login_marker']}")
        print(f"  authed: status={authed['status']:<4} len={authed['len']:<6} login_marker={authed['login_marker']}")
        if jwt:
            print(f"  jwt   : {jwt}")

    sys.exit(0 if verdict == "looks-authenticated" else (2 if verdict == "jwt-expired" else 1))


if __name__ == "__main__":
    main()
