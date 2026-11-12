#!/usr/bin/env python3
"""
cdp-login-session.py — inject the operator's own session into a CDP-attached Chrome.

GAP THIS CLOSES (caught live 2026-10-23): HUNTR's CDP-attach code (browser-capture.py,
js-api-harvest.py, _auto_cdp) assumes the browser it attaches to is ALREADY logged in — it only
ever calls Playwright's addCookies() in the non-CDP fallback branch (a fresh incognito context it
just created), never on a CDP-attached real browser. That's fine the FIRST time an operator
manually logs into the debug Chrome by hand, but the moment that session expires or a fresh/relaunched
Chrome is attached (e.g. _auto_cdp recovering from a dead CDP port), nothing re-applies the cookie
the operator already gave HUNTR in creds.json — so HUNTR sits in front of a login page instead of
using the exact session it was handed, needing a human to log in by hand. "HUNTR must take the
session I provided... not need to login manually" (operator directive).

This tool: connects to a CDP-attached Chrome (same connectOverCDP + newPage()+.context() trick
browser-capture.py already uses to find the REAL default context, not a blank one), injects every
cookie from the operator's cookie string onto the target's own domain via addCookies (works for
HttpOnly cookies too — addCookies goes through CDP's Network.setCookie, not document.cookie),
navigates to the target URL, and reports whether the result looks logged-in.

Usage:
  cdp-login-session.py --cdp-port 9222 --url https://target.example.com/ --cookie "a=1; b=2" [--json]
Emits: {"ok":bool,"injected":N,"final_url":"...","looks_logged_in":bool,"evidence":"..."}
Exit: 0.
"""
import sys, os, json, tempfile, subprocess, re
from urllib.parse import urlparse

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

CDP_PORT = arg("--cdp-port", "")
URL = arg("--url", "")
COOKIE = arg("--cookie", "")

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not CDP_PORT or not URL:
    out({"ok": False, "error": "need --cdp-port and --url"})

HOST = urlparse(URL).hostname or ""

# A page that looks like a login/identity/auth wall after navigating — same signal-words pattern
# already used elsewhere in the engine for "does this response look logged out" checks.
_LOGIN_SIGNS = re.compile(r"(log.?in|sign.?in|/auth(/|$)|/identity(/|$)|/oauth/authorize|password)", re.I)

JS = r"""
const { chromium } = require('playwright');
const CDP_PORT=process.env.CL_CDP_PORT, URL=process.env.CL_URL, COOKIE=process.env.CL_COOKIE||'', HOST=process.env.CL_HOST;
(async()=>{
  let ctx, authMode='none', injected=0;
  try{
    const browser=await chromium.connectOverCDP('http://127.0.0.1:'+CDP_PORT);
    const contexts=browser.contexts();
    if(contexts.length){
      ctx = contexts[0];
    } else {
      // Real user Chrome: browser.contexts() returns [] over CDP. newPage() opens a page in the
      // DEFAULT context (the real profile, real cookies) instead of creating a blank incognito one —
      // same fix already proven in browser-capture.py for the exact same CDP quirk.
      const _seed = await browser.newPage();
      ctx = _seed.context();
      await _seed.close();
    }
  }catch(e){
    console.log(JSON.stringify({ok:false, error:'connect failed: '+String(e).slice(0,200)}));
    return;
  }
  if(COOKIE){
    try{
      const cookies = COOKIE.split(';').map(kv=>{
        const i = kv.indexOf('='); if(i<0) return null;
        const n = kv.slice(0,i).trim(), v = kv.slice(i+1).trim();
        if(!n) return null;
        return {name:n, value:v, url:URL};
      }).filter(Boolean);
      if(cookies.length){
        await ctx.addCookies(cookies);
        injected = cookies.length;
      }
    }catch(e){ /* keep going — report what we can */ }
  }
  const page = await ctx.newPage();
  let finalUrl = URL, err = null;
  // domcontentloaded, not networkidle: live-tested 2026-10-23, networkidle hangs the full 60s
  // timeout on this (and likely most) real SPA — continuous polling/beacons/websockets keep the
  // network "busy" forever, so networkidle's own promise never resolves even with its own timeout
  // option set (CDP-attached pages did not reliably honor it here). domcontentloaded is enough to
  // tell a login/identity redirect from the real app landing.
  try{
    await page.goto(URL, {waitUntil:'domcontentloaded', timeout:15000});
  }catch(e){ err = String(e).slice(0,200); }
  await page.waitForTimeout(1500);   // let the SPA's router/initial render settle a little
  try{ finalUrl = page.url(); }catch(e){}
  let bodyText = '';
  try{ bodyText = (await page.content()).slice(0, 2000); }catch(e){}
  await page.close();
  console.log(JSON.stringify({ok:true, injected, final_url:finalUrl, body_snip:bodyText.slice(0,500), nav_error:err}));
  process.exit(0);
})().catch(e=>{console.log(JSON.stringify({ok:false, error:String(e).slice(0,200)})); process.exit(1);});
// connectOverCDP leaves the WebSocket/CDP connection's event-loop handles open — without an
// explicit process.exit(), node never naturally terminates (caught live 2026-10-23: the script
// completed ALL its work, printed the correct successful result, then hung until the OUTER
// subprocess timeout killed it 60s later — looked exactly like a hang/failure even though the
// actual cookie injection + navigation had already fully succeeded).
"""

tf = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
tf.write(JS); tf.close()
env = dict(os.environ, CL_CDP_PORT=CDP_PORT, CL_URL=URL, CL_COOKIE=COOKIE, CL_HOST=HOST)
np = env.get("NODE_PATH", "")
env["NODE_PATH"] = ":".join(x for x in [np, "/usr/share/nodejs", "/usr/lib/node_modules"] if x)
try:
    r = subprocess.run(["node", tf.name], capture_output=True, text=True, timeout=60, env=env)
    os.unlink(tf.name)
    line = next((l for l in reversed((r.stdout or "").splitlines()) if l.strip().startswith("{")), None)
    res = json.loads(line) if line else {"ok": False, "error": (r.stderr or "no output")[:300]}
except Exception as e:
    res = {"ok": False, "error": str(e)[:200]}

if res.get("ok"):
    final_url = res.get("final_url", "")
    # logged-in heuristic: did we land somewhere that does NOT look like a login/identity wall,
    # and (if we know the original host) are we still on the target's own domain rather than
    # bounced off to a completely different auth provider?
    bounced_to_login = bool(_LOGIN_SIGNS.search(final_url)) or (HOST and HOST not in final_url and "identity" in final_url.lower())
    res["looks_logged_in"] = not bounced_to_login
    res["evidence"] = ("landed on " + final_url) if not bounced_to_login else ("redirected to what looks like a login/identity page: " + final_url)

out(res)
