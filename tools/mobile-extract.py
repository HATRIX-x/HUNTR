#!/usr/bin/env python3
"""
mobile-extract — rip the attack surface from an APK or IPA for bug bounty hunting.

Pulls API endpoints, hardcoded secrets, deep links, exported components,
WebView config, cert-pinning signals, and cloud keys — feeds straight into
HUNTR coverage as a surface list ready to probe.

Uses: aapt (manifest), apktool (smali), jadx (decompiled Java), strings (binary).
Falls back to zipfile + regex when tools are missing — always produces output.

Usage:
  mobile-extract.py --apk app.apk [--json] [--out report.json] [--deep]
  mobile-extract.py --ipa app.ipa [--json] [--out report.json] [--deep]
  mobile-extract.py --apk app.apk --report        # human-readable summary

Flags:
  --deep     run jadx/apktool full decompile (slow, more complete)
  --json     print structured JSON and exit
  --report   human-readable summary
  --out F    write JSON to file F

Exit: 0.
"""
import sys, os, re, json, zipfile, subprocess, tempfile, shutil, struct
from pathlib import Path
from collections import defaultdict

# ── helpers ──────────────────────────────────────────────────────────────────

def arg(n, d=None):
    return sys.argv[sys.argv.index(n)+1] if n in sys.argv else d

def flag(n):
    return n in sys.argv

def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return r.stdout + r.stderr
    except Exception:
        return ""

def which(t):
    return shutil.which(t) is not None

# ── secret / endpoint patterns ────────────────────────────────────────────────

SECRET_PATTERNS = [
    ("aws_key",        r"AKIA[0-9A-Z]{16}"),
    ("aws_secret",     r"(?i)aws.{0,20}secret.{0,10}['\"]([A-Za-z0-9/+]{40})['\"]"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("firebase_url",   r"https?://[a-z0-9-]+\.firebaseio\.com"),
    ("firebase_key",   r"(?i)firebase.{0,20}['\"]([A-Za-z0-9_-]{22,})['\"]"),
    ("jwt_token",      r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*"),
    ("bearer_token",   r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*"),
    ("basic_auth",     r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]+"),
    ("private_key",    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("stripe_key",     r"(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}"),
    ("slack_token",    r"xox[baprs]-[0-9a-zA-Z\-]+"),
    ("github_token",   r"ghp_[A-Za-z0-9]{36}"),
    ("twilio_sid",     r"AC[a-z0-9]{32}"),
    ("generic_secret", r"(?i)(?:api_?key|api_?secret|access_?token|client_?secret|auth_?token|private_?key)\s*[=:]\s*['\"]([A-Za-z0-9\-_.~+/]{16,})['\"]"),
    ("internal_ip",    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    ("password_field", r"(?i)password\s*[=:]\s*['\"]([^'\"]{6,})['\"]"),
    ("hardcoded_url",  r"https?://(?!(?:www\.|cdn\.|fonts\.|schemas\.|example\.com|w3\.org|android\.com|google\.com/fonts)[^\s]*)[a-z0-9.-]{4,}\.[a-z]{2,}/[^\s\"'<>]{2,}"),
]

ENDPOINT_PAT = re.compile(
    r"""(?:["'\s(,=])(https?://[a-zA-Z0-9._\-]+\.[a-zA-Z]{2,}(?:/[^\s"'<>{}|\\^`\[\]]*)?)\b""", re.I
)
DOMAIN_PAT = re.compile(
    r"""(?:["'\s/])((?:[a-z0-9][a-z0-9\-]*\.)+(?:com|io|net|org|app|dev|co|ai|cloud|internal|local)(?:/[^\s"'<>]{0,60})?)\b""", re.I
)
DEEP_LINK_PAT = re.compile(r"""([a-z][a-z0-9+\-.]{2,30})://[^\s"'<>]{2,}""", re.I)
PHONE_PAT = re.compile(r"""\+?[1-9]\d{7,14}""")

NOISE_HOSTS = {
    "schema.org","android.com","google.com","w3.org","apache.org","mozilla.org",
    "openssl.org","ietf.org","example.com","schemas.android.com","schemas.xmlsoap.org",
    "xmlns.com","ns.adobe.com","play.google.com","developer.android.com","material.io",
    "fonts.gstatic.com","fonts.googleapis.com","gstatic.com","googletagmanager.com",
    "crashlytics.com","firebase.google.com","firebasestorage.googleapis.com",
    "googleapis.com","googleapis.com","oauth2.googleapis.com",
}

def is_noise(url):
    try:
        from urllib.parse import urlparse
        h = urlparse(url).netloc.lower().lstrip("www.")
        return any(h == n or h.endswith("."+n) for n in NOISE_HOSTS)
    except Exception:
        return False

# ── string corpus builder ─────────────────────────────────────────────────────

def extract_strings_from_file(path, min_len=6):
    """Extract printable strings from any binary/text file."""
    try:
        if which("strings"):
            out = run_cmd(["strings", "-n", str(min_len), str(path)])
            return out
        data = Path(path).read_bytes()
        # fallback: regex on raw bytes
        matches = re.findall(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data)
        return "\n".join(m.decode("ascii","ignore") for m in matches)
    except Exception:
        return ""

# ── APK analysis ─────────────────────────────────────────────────────────────

def analyze_apk(apk_path, deep=False):
    out = {
        "type": "apk", "file": str(apk_path),
        "package": "", "version": "", "min_sdk": "", "target_sdk": "",
        "permissions": [], "exported_components": [], "deep_links": [],
        "endpoints": [], "secrets": [], "domains": [],
        "cert_pinning": False, "webview_js": False, "root_detection": False,
        "backup_enabled": None, "debug_enabled": False,
        "firebase_config": {}, "notes": [],
    }

    # ── manifest via aapt ──
    if which("aapt"):
        mf = run_cmd(["aapt", "dump", "badging", str(apk_path)], timeout=30)
        if m := re.search(r"package: name='([^']+)'", mf): out["package"] = m.group(1)
        if m := re.search(r"versionName='([^']+)'", mf): out["version"] = m.group(1)
        if m := re.search(r"sdkVersion:'(\d+)'", mf): out["min_sdk"] = m.group(1)
        if m := re.search(r"targetSdkVersion:'(\d+)'", mf): out["target_sdk"] = m.group(1)
        for p in re.findall(r"uses-permission: name='([^']+)'", mf):
            out["permissions"].append(p)

        xmlraw = run_cmd(["aapt", "dump", "xmltree", str(apk_path), "AndroidManifest.xml"], timeout=30)
        # exported components
        current_comp = None
        for line in xmlraw.splitlines():
            if "E: activity " in line or "E: service " in line or "E: receiver " in line or "E: provider " in line:
                kind = re.search(r"E: (\w+) ", line)
                current_comp = {"kind": kind.group(1) if kind else "?", "name": "", "exported": False, "actions": []}
            if current_comp:
                if 'A: android:name' in line and not current_comp["name"]:
                    if m := re.search(r'"([^"]+)"', line): current_comp["name"] = m.group(1)
                if 'A: android:exported' in line and '0x1' in line: current_comp["exported"] = True
                if 'A: android:debuggable' in line and '0x1' in line: out["debug_enabled"] = True
                if 'A: android:allowBackup' in line:
                    out["backup_enabled"] = '0x1' in line
                if 'E: action' in line:
                    if m := re.search(r'"([^"]+)"', line): current_comp["actions"].append(m.group(1))
                # deep links from intent-filter data
                if 'A: android:scheme' in line:
                    if m := re.search(r'"([^"]+)"', line):
                        s = m.group(1)
                        if s not in ("http","https","content","file","mailto","tel"):
                            out["deep_links"].append({"scheme": s, "component": current_comp.get("name","?")})
                if 'A: android:host' in line or 'A: android:pathPrefix' in line:
                    pass  # could enrich deep_links further
                # flush on next component start
            if current_comp and current_comp.get("name") and current_comp.get("exported"):
                if current_comp not in out["exported_components"]:
                    out["exported_components"].append(dict(current_comp))

    # ── string extraction from ZIP contents ──
    corpus = ""
    try:
        with zipfile.ZipFile(str(apk_path)) as z:
            for name in z.namelist():
                # resources, assets, META-INF
                if any(name.startswith(p) for p in ("res/","assets/","META-INF/")) or name.endswith((".xml",".json",".properties",".txt",".pem",".crt",".cfg",".yaml",".yml")):
                    try:
                        data = z.read(name)
                        corpus += data.decode("utf-8","ignore") + "\n"
                    except Exception:
                        pass
                # google-services.json / firebase
                if name == "assets/google-services.json" or name.endswith("google-services.json"):
                    try:
                        gs = json.loads(z.read(name).decode("utf-8","ignore"))
                        out["firebase_config"] = {
                            "project_id": gs.get("project_info",{}).get("project_id",""),
                            "storage_bucket": gs.get("project_info",{}).get("storage_bucket",""),
                            "firebase_url": gs.get("project_info",{}).get("firebase_url",""),
                        }
                        out["notes"].append("google-services.json found — check Firebase rules")
                    except Exception:
                        pass
                # check for cert pinning backup (res/xml/network_security_config.xml)
                if "network_security_config" in name:
                    try:
                        nsc = z.read(name).decode("utf-8","ignore")
                        if "pin-set" in nsc or "pin sha256" in nsc.lower():
                            out["cert_pinning"] = True
                            out["notes"].append("network_security_config has <pin-set> — cert pinning active")
                        if "cleartextTrafficPermitted" in nsc and "true" in nsc:
                            out["notes"].append("cleartextTrafficPermitted=true — HTTP traffic allowed")
                    except Exception:
                        pass
    except Exception as e:
        out["notes"].append(f"ZIP read error: {e}")

    # DEX strings via strings utility
    try:
        with zipfile.ZipFile(str(apk_path)) as z:
            for name in z.namelist():
                if name.endswith(".dex"):
                    with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as tf:
                        tf.write(z.read(name)); tf_name = tf.name
                    corpus += extract_strings_from_file(tf_name) + "\n"
                    Path(tf_name).unlink(missing_ok=True)
    except Exception:
        pass

    # ── deep decompile (optional) ──
    if deep and which("apktool"):
        with tempfile.TemporaryDirectory() as td:
            run_cmd(["apktool", "d", str(apk_path), "-o", td, "-f", "--no-res"], timeout=180)
            for p in Path(td).rglob("*.smali"):
                try: corpus += p.read_text(errors="ignore") + "\n"
                except Exception: pass
            for p in Path(td).rglob("*.xml"):
                try: corpus += p.read_text(errors="ignore") + "\n"
                except Exception: pass

    if deep and which("jadx"):
        with tempfile.TemporaryDirectory() as td:
            run_cmd(["jadx", "-d", td, str(apk_path)], timeout=300)
            for p in Path(td).rglob("*.java"):
                try: corpus += p.read_text(errors="ignore") + "\n"
                except Exception: pass

    _process_corpus(corpus, out)
    return out

# ── IPA analysis ─────────────────────────────────────────────────────────────

def analyze_ipa(ipa_path, deep=False):
    out = {
        "type": "ipa", "file": str(ipa_path),
        "bundle_id": "", "version": "", "min_os": "", "platform": "",
        "permissions": [], "url_schemes": [], "deep_links": [],
        "endpoints": [], "secrets": [], "domains": [],
        "cert_pinning": False, "webview_js": False, "root_detection": False,
        "ats_exceptions": [], "entitlements": [],
        "notes": [],
    }

    corpus = ""
    binary_path = None

    try:
        with zipfile.ZipFile(str(ipa_path)) as z:
            for name in z.namelist():
                # Info.plist
                if name.endswith("Info.plist"):
                    try:
                        raw = z.read(name)
                        text = raw.decode("utf-8","ignore")
                        # XML plist
                        if "<?xml" in text or "<plist" in text:
                            import xml.etree.ElementTree as ET
                            root = ET.fromstring(text)
                            kv = _parse_plist_dict(root.find("dict"))
                            out["bundle_id"] = kv.get("CFBundleIdentifier","")
                            out["version"] = kv.get("CFBundleShortVersionString","")
                            out["min_os"] = kv.get("MinimumOSVersion","")
                            out["platform"] = kv.get("DTPlatformName","ios")
                            # URL schemes
                            for scheme_entry in _plist_get_list(kv, "CFBundleURLTypes"):
                                for s in _plist_get_list(scheme_entry, "CFBundleURLSchemes"):
                                    if s not in ("http","https"):
                                        out["url_schemes"].append(s)
                                        out["deep_links"].append({"scheme": s})
                            # permissions (usage descriptions)
                            for k, v in kv.items():
                                if k.endswith("UsageDescription"):
                                    out["permissions"].append(f"{k}: {str(v)[:80]}")
                            # ATS exceptions
                            ats = kv.get("NSAppTransportSecurity", {})
                            if isinstance(ats, dict):
                                if ats.get("NSAllowsArbitraryLoads"):
                                    out["ats_exceptions"].append("NSAllowsArbitraryLoads=YES — HTTP allowed globally")
                                    out["notes"].append("ATS disabled globally — HTTP traffic allowed")
                                for domain, cfg in ats.get("NSExceptionDomains", {}).items():
                                    out["ats_exceptions"].append(f"{domain}: {cfg}")
                        corpus += text + "\n"
                    except Exception:
                        pass

                # Entitlements
                if "Entitlements" in name or name.endswith(".entitlements"):
                    try:
                        text = z.read(name).decode("utf-8","ignore")
                        corpus += text + "\n"
                        if "keychain-access-groups" in text:
                            out["entitlements"].append("keychain-access-groups")
                        if "com.apple.developer.associated-domains" in text:
                            for d in re.findall(r"applinks:([^\s<\"]+)", text):
                                out["notes"].append(f"Associated domain: {d}")
                    except Exception:
                        pass

                # Assets, plists, JS bundles
                if any(name.endswith(e) for e in (".plist",".json",".js",".html",".txt",".xml",".cfg",".properties")):
                    try: corpus += z.read(name).decode("utf-8","ignore") + "\n"
                    except Exception: pass

                # Main binary (Mach-O) — strings extraction
                if name.endswith(".app/") is False and "/" in name and not name.endswith("/"):
                    # Heuristic: the main binary has no extension and is in Payload/App.app/
                    parts = name.split("/")
                    if len(parts) >= 3 and parts[0] == "Payload" and parts[1].endswith(".app") and len(parts) == 3:
                        try:
                            with tempfile.NamedTemporaryFile(delete=False) as tf:
                                tf.write(z.read(name)); binary_path = tf.name
                        except Exception:
                            pass
    except Exception as e:
        out["notes"].append(f"ZIP read error: {e}")

    if binary_path:
        corpus += extract_strings_from_file(binary_path) + "\n"
        # detect cert pinning signals
        if any(x in corpus for x in ("TrustKit","SSLPinningMode","pinnedPublicKeyHashes","NSURLSession","SecTrustEvaluate")):
            out["cert_pinning"] = True
            out["notes"].append("Cert pinning signals found in binary (TrustKit/NSURLSession)")
        if any(x in corpus for x in ("jailbreak","Cydia","substrate","SBSettings","MobileSubstrate")):
            out["root_detection"] = True
            out["notes"].append("Jailbreak detection strings found")
        Path(binary_path).unlink(missing_ok=True)

    _process_corpus(corpus, out)
    return out

# ── shared corpus analysis ────────────────────────────────────────────────────

def _process_corpus(corpus, out):
    # endpoints
    eps = set()
    for m in ENDPOINT_PAT.finditer(corpus):
        url = m.group(1).rstrip("\"',;)").split("\\")[0]
        if len(url) > 10 and not is_noise(url):
            eps.add(url)
    out["endpoints"] = sorted(eps)

    # domains
    domains = set()
    for m in DOMAIN_PAT.finditer(corpus):
        d = m.group(1).lower()
        if not is_noise("https://"+d) and "." in d and len(d) > 5:
            domains.add(d.split("/")[0])
    out["domains"] = sorted(domains - {d.split("/")[0] for d in out.get("endpoints",[])})[:40]

    # deep links (from corpus, in addition to manifest)
    known_schemes = {dl["scheme"] for dl in out.get("deep_links",[])}
    std = {"http","https","mailto","tel","sms","ftp","file","content","geo","market"}
    for m in DEEP_LINK_PAT.finditer(corpus):
        scheme = m.group(1).lower()
        if scheme not in std and scheme not in known_schemes and len(scheme) > 2:
            out["deep_links"].append({"scheme": scheme, "sample": m.group(0)[:80]})
            known_schemes.add(scheme)

    # secrets
    seen_vals = set()
    for label, pat in SECRET_PATTERNS:
        for m in re.finditer(pat, corpus):
            val = m.group(0)
            if val not in seen_vals and len(val) > 8:
                seen_vals.add(val)
                out["secrets"].append({
                    "type": label,
                    "value": val[:120],
                    "redacted": val[:6] + "…" + val[-4:] if len(val) > 14 else "…",
                })

    # webview javascript enabled
    if any(x in corpus for x in ("setJavaScriptEnabled(true)","javaScriptEnabled","WKWebView","UIWebView","WebView")):
        out["webview_js"] = True

    # root / jailbreak detection
    if any(x in corpus for x in ("isRooted","RootBeer","detectRoot","su\x00","which su","Superuser.apk")):
        out["root_detection"] = True

    # cert pinning (Android signals)
    if any(x in corpus for x in ("CertificatePinner","certificatePinner","TrustManagerFactory","X509TrustManager","OkHttpClient.Builder","pinnedCertificates")):
        out["cert_pinning"] = True

    # dedup
    out["secrets"] = list({s["value"]: s for s in out["secrets"]}.values())

# ── plist helpers ─────────────────────────────────────────────────────────────

def _parse_plist_dict(node):
    if node is None: return {}
    result = {}
    children = list(node)
    i = 0
    while i < len(children) - 1:
        key = children[i].text or ""
        val_node = children[i+1]
        result[key] = _parse_plist_value(val_node)
        i += 2
    return result

def _parse_plist_value(node):
    if node is None: return None
    tag = node.tag
    if tag == "dict": return _parse_plist_dict(node)
    if tag == "array": return [_parse_plist_value(c) for c in node]
    if tag in ("string","real","integer","date","data"): return node.text or ""
    if tag == "true": return True
    if tag == "false": return False
    return node.text or ""

def _plist_get_list(d, key):
    v = d.get(key, [])
    return v if isinstance(v, list) else []

# ── output ────────────────────────────────────────────────────────────────────

def print_report(r):
    t = r["type"].upper()
    print(f"══ MOBILE SURFACE — {t} ═══════════════════════════════")
    if r.get("package"): print(f"  Package : {r['package']} v{r.get('version','?')}")
    if r.get("bundle_id"): print(f"  Bundle  : {r['bundle_id']} v{r.get('version','?')}")
    print(f"  SDK     : min={r.get('min_sdk') or r.get('min_os','?')}  target={r.get('target_sdk','?')}\n")

    print(f"  Endpoints ({len(r['endpoints'])}):")
    for e in r["endpoints"][:30]: print(f"    {e}")
    if len(r["endpoints"]) > 30: print(f"    … +{len(r['endpoints'])-30} more")

    print(f"\n  Secrets ({len(r['secrets'])}):")
    for s in r["secrets"][:20]:
        print(f"    [{s['type']}] {s['redacted']}")
    if len(r["secrets"]) > 20: print(f"    … +{len(r['secrets'])-20} more")

    if r.get("deep_links"):
        print(f"\n  Deep links ({len(r['deep_links'])}):")
        for dl in r["deep_links"][:10]: print(f"    {dl['scheme']}:// → {dl.get('component') or dl.get('sample','')}")

    if r.get("exported_components"):
        print(f"\n  Exported components ({len(r['exported_components'])}):")
        for c in r["exported_components"][:10]:
            print(f"    [{c['kind']}] {c['name']} — actions: {', '.join(c.get('actions',[]))[:60]}")

    if r.get("permissions"):
        dangerous = [p for p in r["permissions"] if any(d in p for d in ("CAMERA","MICROPHONE","LOCATION","CONTACTS","STORAGE","SMS","PHONE","RECORD"))]
        print(f"\n  Permissions: {len(r['permissions'])} total, {len(dangerous)} dangerous")
        for p in dangerous[:10]: print(f"    ⚠ {p}")

    flags = []
    if r.get("cert_pinning"): flags.append("cert pinning")
    if r.get("webview_js"): flags.append("WebView JS enabled")
    if r.get("root_detection"): flags.append("root/jailbreak detection")
    if r.get("debug_enabled"): flags.append("⚠ android:debuggable=true")
    if r.get("backup_enabled") is True: flags.append("⚠ android:allowBackup=true")
    if r.get("ats_exceptions"): flags.append(f"ATS exceptions ({len(r['ats_exceptions'])})")
    if flags: print(f"\n  Flags: {', '.join(flags)}")

    if r.get("notes"):
        print("\n  Notes:")
        for n in r["notes"]: print(f"    → {n}")

    print(f"\n  Domains ({min(len(r.get('domains',[])),10)}/{len(r.get('domains',[]))}) — top 10:")
    for d in r.get("domains",[])[:10]: print(f"    {d}")

def main():
    apk = arg("--apk")
    ipa = arg("--ipa")
    deep = flag("--deep")

    if not apk and not ipa:
        print(__doc__); sys.exit(0)

    path = apk or ipa
    if not Path(path).exists():
        sys.exit(f"[mobile-extract] file not found: {path}")

    print(f"[mobile-extract] analyzing {Path(path).name} …", file=sys.stderr)
    result = analyze_apk(path, deep=deep) if apk else analyze_ipa(path, deep=deep)

    out_file = arg("--out")
    if out_file:
        Path(out_file).write_text(json.dumps(result, indent=2))
        print(f"[mobile-extract] wrote {out_file}", file=sys.stderr)

    if flag("--json"):
        print(json.dumps(result)); return

    print_report(result)

if __name__ == "__main__":
    main()
