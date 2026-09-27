#!/usr/bin/env python3
"""
oauth-probe — static + light-active audit of an OAuth2 / OIDC authorize+token
flow for the classic misconfigurations.

Checks (no destructive actions, no code exchange unless a code is supplied):
  · redirect_uri open-redirect / lax matching (subdomain, suffix, path append,
    userinfo trick, //evil, %2f, appended-param, http downgrade)
  · state parameter missing → CSRF (login/account-link forgery)
  · implicit flow available (response_type=token → token in URL fragment leaks)
  · PKCE downgrade (server issues code with no code_challenge)
  · scope escalation (extra scopes echoed back / not rejected)
  · token endpoint reachable over http:// (downgrade)
  · authorization-code reuse (if --code given: second exchange should 400)

Usage:
  oauth-probe.py --auth-url https://id.acme.com/oauth/authorize \
                 --token-url https://id.acme.com/oauth/token \
                 --client-id abc --redirect-uri https://app.acme.com/cb \
                 [--scope "openid profile"] [--code AUTH_CODE] [--json]
Only test IdPs / clients you are authorized to assess.
Exit: 0 clean · 1 findings.
"""
import sys, json, time, ssl
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def send(url, method="GET", data=None, headers=None, follow=False):
    class NoRedirect(__import__("urllib.request", fromlist=["HTTPRedirectHandler"]).HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            if follow:
                return super().redirect_request(req, fp, code, msg, hdrs, newurl)
            return None
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler(), NoRedirect())
    body = data.encode() if isinstance(data, str) else data
    req = Request(url, data=body, headers=headers or {"User-Agent": "Mozilla/5.0"}, method=method)
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read(8192).decode("utf-8", "ignore")
    except HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(4096).decode("utf-8", "ignore") if e.fp else "")
    except Exception as ex:
        return 0, {}, str(ex)[:200]


def authorize_url(auth_url, client_id, redirect_uri, scope, response_type="code",
                  state=None, extra=None):
    q = {"client_id": client_id, "redirect_uri": redirect_uri,
         "response_type": response_type, "scope": scope}
    if state is not None:
        q["state"] = state
    if extra:
        q.update(extra)
    sep = "&" if "?" in auth_url else "?"
    return f"{auth_url}{sep}{urlencode(q)}"


def location_host(headers):
    loc = headers.get("Location") or headers.get("location") or ""
    try:
        return loc, urlparse(loc).netloc.lower()
    except Exception:
        return loc, ""


def main():
    auth_url = arg("--auth-url")
    token_url = arg("--token-url")
    client_id = arg("--client-id", "")
    redirect_uri = arg("--redirect-uri", "")
    scope = arg("--scope", "openid profile email")
    code = arg("--code")

    if not auth_url:
        print(__doc__)
        sys.exit(0)

    findings = []
    reg_host = urlparse(redirect_uri).netloc.lower() if redirect_uri else ""
    reg_scheme = urlparse(redirect_uri).scheme if redirect_uri else "https"

    # 1) redirect_uri manipulation
    evil = "evil.example"
    variants = []
    if redirect_uri:
        base = redirect_uri.rstrip("/")
        variants = [
            ("subdomain", base.replace(reg_host, f"{reg_host}.{evil}") if reg_host else base),
            ("suffix_host", base.replace(reg_host, f"{reg_host}{evil}") if reg_host else base),
            ("path_append", base + f"/../../@{evil}/"),
            ("userinfo_trick", f"{reg_scheme}://{reg_host}@{evil}/cb"),
            ("double_slash", f"{reg_scheme}://{evil}//{reg_host}/cb"),
            ("encoded_slash", base + f"%2f%2f{evil}"),
            ("append_param", base + f"?next=https://{evil}/"),
            ("http_downgrade", base.replace("https://", "http://", 1)),
        ]
    for name, ruri in variants:
        u = authorize_url(auth_url, client_id, ruri, scope, state="probe")
        s, h, _ = send(u)
        loc, lhost = location_host(h)
        leaked = bool(lhost) and evil in lhost and (reg_host and lhost != reg_host)
        if leaked or (s in (301, 302, 303, 307, 308) and evil in (loc or "")):
            findings.append({
                "test": "redirect_uri_bypass",
                "variant": name,
                "severity": "high",
                "detail": f"authorize accepted attacker redirect_uri ({name}); "
                          f"Location → {loc[:120]}",
                "poc_url": u,
            })

    # 2) state / CSRF
    u_nostate = authorize_url(auth_url, client_id, redirect_uri, scope, state=None)
    s, h, body = send(u_nostate)
    if s in (200, 301, 302, 303, 307, 308) and "state" not in (h.get("Location", "").lower()):
        findings.append({
            "test": "missing_state_csrf",
            "severity": "medium",
            "detail": "authorize proceeds without a state parameter — no CSRF binding "
                      "on the callback (login/account-link CSRF).",
            "poc_url": u_nostate,
        })

    # 3) implicit flow (token in fragment)
    u_impl = authorize_url(auth_url, client_id, redirect_uri, scope,
                           response_type="token", state="probe")
    s, h, _ = send(u_impl)
    if s in (200, 302, 303, 307) and "unsupported_response_type" not in (h.get("Location", "")):
        findings.append({
            "test": "implicit_flow_enabled",
            "severity": "medium",
            "detail": "response_type=token accepted — access token returned in URL "
                      "fragment (leaks via Referer/history/logs).",
            "poc_url": u_impl,
        })

    # 4) PKCE downgrade
    u_nopkce = authorize_url(auth_url, client_id, redirect_uri, scope, state="probe")
    s, h, _ = send(u_nopkce)
    loc, _ = location_host(h)
    if s in (302, 303, 307) and "code=" in (loc or "") and "code_challenge" not in u_nopkce:
        findings.append({
            "test": "pkce_downgrade",
            "severity": "medium",
            "detail": "authorization code issued with no code_challenge — PKCE not "
                      "enforced; public clients exposed to code interception.",
            "poc_url": u_nopkce,
        })

    # 5) scope escalation
    esc = (scope + " admin openid offline_access").strip()
    u_scope = authorize_url(auth_url, client_id, redirect_uri, esc, state="probe")
    s, h, _ = send(u_scope)
    loc, _ = location_host(h)
    if s in (302, 303, 307) and "invalid_scope" not in (loc or ""):
        findings.append({
            "test": "scope_escalation",
            "severity": "low",
            "detail": "elevated scopes (admin/offline_access) not rejected at authorize "
                      "— verify the issued token honours only granted scopes.",
            "poc_url": u_scope,
        })

    # 6) token endpoint http downgrade
    if token_url and token_url.startswith("https://"):
        http_tok = token_url.replace("https://", "http://", 1)
        s, h, _ = send(http_tok, method="POST",
                       data=urlencode({"grant_type": "client_credentials",
                                       "client_id": client_id}),
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        if s and s not in (0,) and not (300 <= s < 400 and (h.get("Location", "").startswith("https"))):
            findings.append({
                "test": "token_endpoint_http",
                "severity": "medium",
                "detail": f"token endpoint answered over cleartext http ({s}) instead of "
                          f"forcing https — tokens exchangeable on an interceptable channel.",
                "poc_url": http_tok,
            })

    # 7) authorization-code reuse (only if a real code is provided)
    if code and token_url:
        form = urlencode({"grant_type": "authorization_code", "code": code,
                          "client_id": client_id, "redirect_uri": redirect_uri})
        hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        s1, _, _ = send(token_url, method="POST", data=form, headers=hdr)
        s2, _, _ = send(token_url, method="POST", data=form, headers=hdr)
        if s1 == 200 and s2 == 200:
            findings.append({
                "test": "auth_code_reuse",
                "severity": "high",
                "detail": "the same authorization code was exchanged twice with 200 — "
                          "codes are not single-use (replay → token minting).",
                "poc_url": token_url,
            })

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "auth_url": auth_url, "token_url": token_url,
        "total": len(findings),
        "findings": findings,
    }

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if findings else 0)

    print(f"\n== oauth-probe · {auth_url} ==")
    print(f"  {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f['severity'].upper():<8}] {f['test']}"
              + (f"/{f.get('variant')}" if f.get('variant') else "")
              + f"\n            {f['detail'][:100]}")
    if not findings:
        print("  no OAuth misconfig detected with static probes.")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
