#!/usr/bin/env python3
"""
browser-capture.py — capture the REAL authenticated API surface of a SPA by driving a real browser.

For AUTHORIZED testing. Loads the operator's session cookies into a real Chromium, navigates the app,
and records every XHR/fetch the SPA makes to the target's own hosts — the exact endpoints, methods, and
request BODIES (the params) the application actually uses. That real call list (with correct params) is
what the exploit agent should test for IDOR / logic, instead of guessing. Read-only.

Implementation note: this env's Python Playwright driver is broken, so this shells out to NODE Playwright
(which works). Needs node with the `playwright` module resolvable (NODE_PATH).

Usage:
  browser-capture.py --url https://app.example.com/ --cookie "a=1; b=2" [--ua "..."] \
      [--hosts example.com] [--secs 14] [--chrome /usr/bin/chromium] [--out calls.json] [--json]
Emits: {"calls":[{"method","path","url","type","status","req_body"}], "count":N}
"""
import sys, os, re, json, tempfile, subprocess

def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d

URL = arg("--url"); COOKIE = arg("--cookie", ""); UA = arg("--ua", "Mozilla/5.0 yeswehack")
SECS = int(arg("--secs", "14") or 14); OUT = arg("--out")
CHROME = arg("--chrome") or next((b for b in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome") if os.path.exists(b)), "/usr/bin/chromium")
HOSTS = arg("--hosts")
if URL and not HOSTS:
    HOSTS = ".".join(re.sub(r"^https?://", "", URL).split("/")[0].split(":")[0].split(".")[-2:])

def out(d):
    print(json.dumps(d)); sys.exit(0)

if not URL:
    out({"calls": [], "error": "no --url"})

JS = r"""
const { chromium } = require('playwright');
const URL=process.env.BC_URL, COOKIE=process.env.BC_COOKIE||'', UA=process.env.BC_UA,
      HOST=process.env.BC_HOST, SECS=parseInt(process.env.BC_SECS||'14',10), CHROME=process.env.BC_CHROME;
const APIISH=/(\/cgi-bin\/|\/api\/|\/v\d+\/|\/index\/service\/|action=|\/graphql)/i;
(async()=>{
  const calls={};
  const b=await chromium.launch({executablePath:CHROME,headless:true,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
  const ctx=await b.newContext({userAgent:UA,ignoreHTTPSErrors:true});
  if(COOKIE){ await ctx.addCookies(COOKIE.split(';').map(kv=>{const [n,...r]=kv.trim().split('=');return {name:n.trim(),value:r.join('=').trim(),domain:'.'+HOST,path:'/',secure:true};})); }
  const page=await ctx.newPage();
  page.on('request',req=>{try{const u=req.url();if(!u.includes(HOST))return;const rt=req.resourceType();
    if(rt!=='xhr'&&rt!=='fetch'&&!APIISH.test(u))return;const k=req.method()+' '+u.split('#')[0];if(calls[k])return;
    let body='';try{body=(req.postData()||'').slice(0,400);}catch(e){}
    calls[k]={method:req.method(),url:u.slice(0,400),path:u.replace(/^https?:\/\/[^/]+/,'').slice(0,300),type:rt,status:null,req_body:body};}catch(e){}});
  page.on('response',r=>{try{const k=r.request().method()+' '+r.url().split('#')[0];if(calls[k]&&calls[k].status===null)calls[k].status=r.status();}catch(e){}});
  try{await page.goto(URL,{waitUntil:'networkidle',timeout:30000});}catch(e){try{await page.goto(URL,{waitUntil:'domcontentloaded',timeout:20000});}catch(e2){}}
  await page.waitForTimeout(SECS*1000);
  for(const sel of ['nav a','[role="navigation"] a','a[href*="measure"]','a[href*="device"]']){try{const els=await page.$$(sel);for(const el of els.slice(0,3)){await el.click({timeout:2000}).catch(()=>{});await page.waitForTimeout(2500);}}catch(e){}}
  await b.close();
  const arr=Object.values(calls);
  console.log(JSON.stringify({calls:arr,count:arr.length}));
})().catch(e=>console.log(JSON.stringify({calls:[],error:String(e).slice(0,200)})));
"""

tf = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
tf.write(JS); tf.close()
env = dict(os.environ, BC_URL=URL, BC_COOKIE=COOKIE, BC_UA=UA, BC_HOST=HOSTS or "", BC_SECS=str(SECS), BC_CHROME=CHROME)
np = env.get("NODE_PATH", "")
env["NODE_PATH"] = ":".join(x for x in [np, "/usr/share/nodejs", "/usr/lib/node_modules"] if x)
try:
    r = subprocess.run(["node", tf.name], capture_output=True, text=True, timeout=SECS + 120, env=env)
    os.unlink(tf.name)
    line = next((l for l in reversed((r.stdout or "").splitlines()) if l.strip().startswith("{")), None)
    res = json.loads(line) if line else {"calls": [], "error": (r.stderr or "no output")[:160]}
except Exception as e:
    res = {"calls": [], "error": str(e)[:160]}
if OUT:
    try: open(OUT, "w").write(json.dumps(res, indent=2))
    except Exception: pass
out(res)
