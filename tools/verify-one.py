#!/usr/bin/env python3
"""
verify-one.py — re-run the AI judge on a SINGLE finding in a hunt's run.json.

Reads finding[fi], sends its real evidence to the strong model (same judge prompt
as hunt-run.phase_ai_judge), applies verdict + repro + impact + remediation + cvss
back to the finding, writes run.json atomically, and emits the updated finding.

Auth: Claude Pro OAuth via llm_client (never the Anthropic API key directly).

Usage: verify-one.py --run /path/run.json --fi 3 [--json]
Emits: {"ok":true,"verdict":"confirmed|likely|false_positive","dropped":bool,"finding":{...}}
"""
import sys, json, importlib.util, re, os, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def out(d):
    print(json.dumps(d)); sys.exit(0)


RUN = arg("--run"); FI = arg("--fi")
if not RUN or FI is None:
    out({"ok": False, "error": "need --run and --fi"})

try:
    fi = int(FI)
except Exception:
    out({"ok": False, "error": "bad --fi"})

rf = Path(RUN)
try:
    d = json.loads(rf.read_text())
except Exception as e:
    out({"ok": False, "error": "cannot read run.json: " + str(e)[:140]})

finds = d.get("findings", [])
if not (0 <= fi < len(finds)):
    out({"ok": False, "error": "fi out of range"})

f = finds[fi]

# ── load llm_client (OAuth-aware) ──
try:
    spec = importlib.util.spec_from_file_location("llm_client", str(HERE / "llm_client.py"))
    lc = importlib.util.module_from_spec(spec); spec.loader.exec_module(lc)
except Exception as e:
    out({"ok": False, "error": "llm_client import failed: " + str(e)[:140]})


def extract_json(txt):
    if not txt:
        return None
    s = txt.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s); s = re.sub(r"\s*```$", "", s)
    try:
        return json.loads(s)
    except Exception:
        pass
    m = re.search(r"\{.*\}", s, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
    return None


evidence = (f.get("detail") or f.get("vuln_detail") or "")[:1200]

# ── PROOF FIRST (XBOW-grade): run the AI proof agent (deterministically gated). A definitive
# proven verdict is authoritative and skips the softer LLM judge. proven=None → fall through. ──
if "--no-proof" not in sys.argv:
    try:
        payload = json.dumps({"finding": {"cls": f.get("cls", ""), "endpoint": f.get("endpoint", ""),
                              "title": f.get("title", ""), "detail": f.get("detail", ""), "param": f.get("param", "")}})
        pr = subprocess.run([sys.executable, str(HERE / "proof.py")], input=payload,
                            capture_output=True, text=True, timeout=160, env=os.environ)
        pd = json.loads((pr.stdout or "").strip().splitlines()[-1])
        if pd.get("ok"):
            pv = pd.get("proven")
            f["proof_method"] = pd.get("method", "")
            f["proof_evidence"] = pd.get("evidence", "")
            if pv is True and not f.get("_det"):
                f["proven"] = True
                # ALSO set f["proof"]["proven"] — the convention hunt-run.py's _proven() actually
                # checks (phase_hard_triage, phase_adversarial_verify, phase_ai_judge's oracle_proven).
                # This key was flat f["proven"] only; _proven() never recognized it, so a finding
                # proven RIGHT HERE by the deterministic proof agent would still get wrongly
                # downgraded to a lead by phase_hard_triage's "no real proof -> lead" rule two
                # phases later — the exact kind of self-contradicting state this trust boundary
                # exists to prevent.
                f["proof"] = {"proven": True, "method": pd.get("method", "proof-agent"),
                              "evidence": str(pd.get("evidence", ""))[:300]}
                f["verdict"] = "confirmed"
                f["impact_text"] = (f.get("impact_text", "") + " · [PROVEN: " + str(pd.get("evidence", ""))[:200] + "]").strip(" ·")
                f["reverified"] = True; f["ai_report"] = True
                _tmp = RUN.with_suffix(".json.tmp"); _tmp.write_text(json.dumps(d)); _tmp.replace(RUN)
                out({"ok": True, "verdict": "confirmed", "dropped": False, "proven": True, "finding": f})
            elif pv is False:
                f["proven"] = False
                f["proof"] = {"proven": False, "method": pd.get("method", "proof-agent"),
                              "evidence": str(pd.get("evidence", ""))[:300]}
                f["verdict"] = "false_positive"
                f["judge_disputed"] = True
                f["judge_reason"] = "proof agent could not reproduce it: " + str(pd.get("evidence", ""))[:250]
                f["reverified"] = True
                _tmp = RUN.with_suffix(".json.tmp"); _tmp.write_text(json.dumps(d)); _tmp.replace(RUN)
                out({"ok": True, "verdict": "false_positive", "dropped": True, "proven": False, "finding": f})
            # proven is None → no deterministic proof possible; continue to the LLM judge below
    except Exception:
        pass

# ── judge REALITY, not stale text: re-fetch the endpoint live and feed the real response ──
# This is the key FP-killer: a finding's stored evidence is the scanner's CLAIM; the live
# response is the truth (e.g. a 200 + x-middleware-rewrite is NOT an open redirect).
ep = (f.get("endpoint") or "").strip()
live = ""
if ep.startswith("http"):
    try:
        hl_spec = importlib.util.spec_from_file_location("huntrlib", str(HERE / "huntrlib.py"))
        hl = importlib.util.module_from_spec(hl_spec); hl_spec.loader.exec_module(hl)
        r = hl.spine(ep, method="GET")
        if r.get("headers"):
            live = ("\n\nLIVE RESPONSE (fetched now — judge from THIS, it is ground truth):\n"
                    + r["headers"][:1500] + "\n[body]\n" + (r.get("body") or "")[:1000])
    except Exception:
        live = ""

item = {"i": 0, "title": f.get("title", ""), "cls": f.get("cls", ""),
        "endpoint": ep, "sev": f.get("sev", ""),
        "cvss": f.get("cvss", ""), "evidence": evidence + live}

sys_p = ("You are a senior bug-bounty validator. You get a finding plus the scanner's claim AND (usually) the "
         "LIVE RESPONSE fetched right now. Judge HONESTLY from the LIVE RESPONSE first — scanners produce many "
         "false positives. HARD RULES:\n"
         "• Open redirect: confirmed ONLY if the live response is a 3xx with a Location header pointing to the "
         "EXTERNAL domain. A 200, an x-middleware-rewrite/internal rewrite, or the param merely reflected in a "
         "canonical tag is NOT a redirect → false_positive.\n"
         "• Exposed 'keys': NEXT_PUBLIC_* values, reCAPTCHA SITE keys, Mixpanel PROJECT tokens, WalletConnect "
         "PROJECT ids, Sentry PUBLIC DSN keys, analytics/tracking ids are PUBLIC BY DESIGN — they are shipped to "
         "every browser and grant no privileged action. Set verdict=false_positive OR severity 'i' (info); never "
         "high/medium. Only a real secret (private API key, server token, DB cred, signing secret that actually "
         "authenticates) is a true finding.\n"
         "• Sentry public key cannot READ errors (only submit); do not claim log/stack-trace access.\n"
         "• CORS: needs ACAO reflecting attacker origin AND credentials:true. XSS/SSTI: payload must execute "
         "unescaped in the live body.\n"
         "Reply STRICT JSON: {\"judgments\":[{\"i\":0,\"verdict\":\"confirmed|likely|false_positive\",\"drop\":bool,"
         "\"sev\":\"c|h|m|l|i\",\"repro\":\"numbered steps grounded in the live response; empty if not demonstrable\","
         "\"impact\":\"concrete, truthful impact in 1-2 sentences\",\"remediation\":\"the fix\",\"cvss\":\"x.x\","
         "\"reason\":\"when drop/false_positive: the concrete disproof quoting the live response\"}]}. "
         "Never inflate. If the live response doesn't support the finding, set false_positive + drop=true + reason.")

payload = json.dumps({"target": d.get("target", ""), "findings": [item]})

text = None
# Haiku first: fast + available; Sonnet is rate-limited (429) on Pro and its retry backoff
# would stall the re-verify for minutes. Haiku 4.5 judges these reliably.
for mdl in (("claude-haiku-4-5-20251001", 90), ("claude-sonnet-4-6", 120)):
    try:
        text, err = lc.call_llm(sys_p, payload, model=mdl[0], provider="anthropic",
                                max_tokens=1600, timeout=mdl[1])
    except Exception as e:
        text, err = None, str(e)
    if text:
        break

if not text:
    out({"ok": False, "error": "LLM unavailable: " + str(err or "")[:160]})

parsed = extract_json(text)
if not isinstance(parsed, dict):
    out({"ok": False, "error": "could not parse judge reply"})

judgments = parsed.get("judgments") or []
j = judgments[0] if judgments and isinstance(judgments[0], dict) else {}
if not j:
    out({"ok": False, "error": "judge returned no judgment"})

dropped = False
verdict = (j.get("verdict") or "").strip()

# ── self-critique: before accepting a confirmation, make the model argue AGAINST it ──
# A confirmed finding only survives if an adversarial pass cannot produce a concrete disproof.
# This is the single biggest false-positive killer; one extra call, only on confirmations.
if verdict in ("confirmed", "likely") and not j.get("drop"):
    crit_sys = ("You are a skeptical senior triager trying to REJECT a bug as a false positive. "
                "Given the finding and the evidence another analyst used to confirm it, find the strongest "
                "concrete reason it is NOT actually exploitable (payload escaped, 200 not 3xx, public-by-design "
                "key, redirect only internal-rewrite, endpoint behind auth returning nothing, etc.). "
                "Reply STRICT JSON: {\"holds\":bool,\"disproof\":\"the concrete reason it fails, or empty if it "
                "genuinely holds\"}. Set holds=false ONLY with a concrete, evidence-grounded disproof — do not "
                "reject on vague doubt.")
    crit_user = json.dumps({"finding": {"title": f.get("title"), "cls": f.get("cls"),
                            "endpoint": f.get("endpoint"), "sev": f.get("sev")},
                            "confirming_evidence": item["evidence"],
                            "confirm_repro": j.get("repro", "")})[:3000]
    ctext = None
    for cm in ("claude-haiku-4-5-20251001", "claude-sonnet-4-6"):
        try:
            ctext, _ce = lc.call_llm(crit_sys, crit_user, model=cm, provider="anthropic", max_tokens=500, timeout=60)
        except Exception:
            ctext = None
        if ctext:
            break
    crit = extract_json(ctext) if ctext else None
    if isinstance(crit, dict) and crit.get("holds") is False:
        disproof = str(crit.get("disproof") or "").strip()
        if len(disproof) >= 40 and not f.get("_det"):
            # the critic produced a real disproof on a non-deterministic finding → override to FP
            j = {"verdict": "false_positive", "drop": True, "reason": "self-critique: " + disproof}
            verdict = "false_positive"
        elif disproof:
            # keep it but flag for human eyes
            f["critique_note"] = disproof[:300]

if j.get("drop") or verdict == "false_positive":
    reason = str(j.get("reason") or "").strip()
    if f.get("_det") and len(reason) < 40:
        # tool-confirmed evidence stands when the judge offers no concrete disproof
        f["verdict"] = "confirmed"
        f["judge_disputed"] = True
        f["detail"] = (f.get("detail", "") + " · note: judge flagged for review without a concrete "
                       "disproof; tool evidence stands").strip(" ·")
    else:
        f["verdict"] = "false_positive"
        f["judge_disputed"] = True
        f["judge_reason"] = reason or "(no reason given)"
        dropped = True
else:
    if j.get("repro"):
        r = j["repro"]
        f["steps"] = "\n".join(str(x) for x in r) if isinstance(r, (list, tuple)) else str(r)
    if j.get("impact"):
        f["impact_text"] = str(j["impact"])
    if j.get("remediation"):
        f["remediation"] = str(j["remediation"])
    if j.get("cvss"):
        f["cvss"] = str(j["cvss"]) or f.get("cvss", "")
    # honor a severity downgrade (e.g. public-by-design key → info)
    js = str(j.get("sev") or "").strip().lower()[:1]
    if js in ("c", "h", "m", "l", "i"):
        f["sev"] = js
    if not (f.get("_det") and verdict != "confirmed"):
        f["verdict"] = verdict or f.get("verdict", "likely")

# deterministic belt-and-suspenders: a public-by-design key is never high/medium, whatever the LLM said
try:
    _s2 = importlib.util.spec_from_file_location("fp_rules", str(HERE / "fp_rules.py"))
    _fpr = importlib.util.module_from_spec(_s2); _s2.loader.exec_module(_fpr)
    _dg, _why = _fpr.should_downgrade(f.get("title", ""), f.get("detail", ""), f.get("cls", ""))
    if _dg and f.get("sev") in ("c", "h", "m", "l"):
        f["sev"] = "i"
        if f.get("verdict") in ("confirmed", "likely"):
            f["verdict"] = "needs_review"
        f["impact_text"] = (f.get("impact_text", "") + " · [auto-info: " + _why + "]").strip(" ·")
except Exception:
    pass

f["reverified"] = True
f["ai_report"] = True

# ── atomic write ──
try:
    tmp = rf.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d)); tmp.replace(rf)
except Exception as e:
    out({"ok": False, "error": "write failed: " + str(e)[:140]})

out({"ok": True, "verdict": f.get("verdict", ""), "dropped": dropped, "finding": f})
