"""
Web pages — signup, login, account, install script.
Served at the root of huntr-cloud.fly.dev so users can sign up
without needing the local agent first.
"""
import os
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, PlainTextResponse

router = APIRouter(tags=["web"])

APP_URL = os.environ.get("APP_URL", "https://huntr-cloud.fly.dev")

# ── shared CSS / brand tokens ────────────────────────────────────────────
_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0A0714;--bg2:#110D1F;--surface:rgba(255,255,255,0.06);
  --border:rgba(255,255,255,0.10);--border2:rgba(255,255,255,0.16);
  --text:#F3F1FB;--text2:#C6C0E2;--text3:#948CB6;
  --accent:#A78BFA;--accent2:rgba(167,139,250,0.15);
  --gold:#E7C983;--green:#4ADE80;--red:#FB7185;
  --sans:'Manrope',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;
}
html,body{min-height:100%;background:var(--bg);color:var(--text);font-family:var(--sans);-webkit-font-smoothing:antialiased}
body{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:24px}

/* orbs */
.orbs{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
.orb{position:absolute;border-radius:50%}
.orb1{width:700px;height:600px;top:-200px;left:-150px;background:radial-gradient(circle,rgba(109,40,217,0.40) 0%,transparent 65%);filter:blur(80px)}
.orb2{width:600px;height:600px;top:-100px;right:-150px;background:radial-gradient(circle,rgba(167,139,250,0.25) 0%,transparent 65%);filter:blur(90px)}

/* card */
.card{position:relative;z-index:1;background:rgba(255,255,255,0.055);border:1px solid var(--border2);border-radius:18px;padding:40px;width:100%;max-width:440px;backdrop-filter:blur(24px)}
.logo{display:flex;align-items:center;gap:10px;font-size:20px;font-weight:900;letter-spacing:-0.03em;margin-bottom:32px;justify-content:center}
.logo span{color:var(--accent)}
.card h1{font-size:22px;font-weight:800;letter-spacing:-0.02em;margin-bottom:6px}
.card .sub{font-size:14px;color:var(--text3);margin-bottom:28px}
label{display:block;font-size:11px;color:var(--text3);margin-bottom:5px}
input[type=email],input[type=password],input[type=text]{
  width:100%;background:rgba(255,255,255,0.05);border:1px solid var(--border2);
  border-radius:9px;padding:11px 14px;font-family:var(--sans);font-size:14px;
  color:var(--text);outline:none;transition:border-color 0.15s;margin-bottom:16px
}
input:focus{border-color:var(--accent)}
.btn{
  width:100%;padding:12px;border:none;border-radius:10px;font-family:var(--sans);
  font-size:15px;font-weight:700;cursor:pointer;transition:all 0.15s;
  background:linear-gradient(135deg,#A78BFA,#7C3AED);color:#fff;
  box-shadow:0 4px 20px -4px rgba(167,139,250,0.4)
}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 28px -4px rgba(167,139,250,0.55)}
.btn:disabled{opacity:0.6;cursor:not-allowed;transform:none}
.err{background:rgba(251,113,133,0.12);border:1px solid rgba(251,113,133,0.25);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--red);margin-bottom:16px;display:none}
.foot{margin-top:20px;text-align:center;font-size:13px;color:var(--text3)}
.foot a{color:var(--accent);text-decoration:none}

/* success panel */
.success{display:none;flex-direction:column;gap:16px}
.success h2{font-size:18px;font-weight:800;color:var(--green);letter-spacing:-0.02em}
.token-box{background:rgba(0,0,0,0.4);border:1px solid var(--border2);border-radius:10px;padding:14px 16px;font-family:var(--mono);font-size:12px;color:var(--accent);word-break:break-all;position:relative}
.copy-btn{position:absolute;top:8px;right:8px;background:var(--accent2);border:1px solid rgba(167,139,250,0.25);border-radius:6px;padding:4px 10px;font-size:11px;font-family:var(--sans);color:var(--accent);cursor:pointer}
.step{display:flex;gap:12px;align-items:flex-start}
.step-num{width:24px;height:24px;border-radius:50%;background:var(--accent2);border:1px solid rgba(167,139,250,0.25);font-size:11px;font-weight:700;color:var(--accent);display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
.step-text{font-size:13px;color:var(--text2);line-height:1.55}
.step-text strong{color:var(--text);display:block;margin-bottom:4px;font-size:13px}
.cmd{background:rgba(0,0,0,0.4);border:1px solid var(--border);border-radius:7px;padding:9px 12px;font-family:var(--mono);font-size:11.5px;color:var(--gold);margin-top:6px;position:relative}
</style>
"""

# ── signup page ──────────────────────────────────────────────────────────
_SIGNUP_HTML = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HUNTR — Create account</title>{_CSS}</head>
<body>
<div class="orbs"><div class="orb orb1"></div><div class="orb orb2"></div></div>
<div class="card">
  <div class="logo">HUNTR<span>.</span></div>

  <!-- signup form -->
  <div id="form-wrap">
    <h1>Create your account</h1>
    <p class="sub">Get the agent token, install in 30 seconds.</p>
    <div class="err" id="err"></div>
    <label>Email</label>
    <input type="email" id="email" placeholder="you@example.com" autocomplete="email">
    <label>Password</label>
    <input type="password" id="pwd" placeholder="min 8 characters" autocomplete="new-password">
    <button class="btn" id="btn" onclick="doSignup()">Create account</button>
    <div class="foot">Already have an account? <a href="/login">Sign in</a></div>
  </div>

  <!-- success -->
  <div class="success" id="success">
    <h2>✓ You're in</h2>
    <p style="font-size:13px;color:var(--text3)">Save your agent token — it's shown once here.</p>
    <div style="position:relative">
      <div class="token-box" id="tok-display"></div>
      <button class="copy-btn" onclick="copyToken()">copy</button>
    </div>
    <div style="display:flex;flex-direction:column;gap:14px;margin-top:4px">
      <div class="step">
        <div class="step-num">1</div>
        <div class="step-text">
          <strong>Install the agent</strong>
          Run this in your terminal (Python 3.10+ required):
          <div class="cmd" id="install-cmd" style="padding-right:48px"></div>
          <button class="copy-btn" style="position:absolute;top:8px;right:8px" onclick="copyInstall()">copy</button>
        </div>
      </div>
      <div class="step">
        <div class="step-num">2</div>
        <div class="step-text">
          <strong>Open the dashboard</strong>
          The installer launches HUNTR at <span style="font-family:var(--mono);color:var(--accent);font-size:12px">127.0.0.1:8899</span> — open it in your browser.
        </div>
      </div>
      <div class="step">
        <div class="step-num">3</div>
        <div class="step-text">
          <strong>Start hunting</strong>
          Paste a HackerOne / Bugcrowd / Intigriti program page and hit Hunt.
        </div>
      </div>
    </div>
    <a href="/login" style="display:block;text-align:center;font-size:13px;color:var(--text3);margin-top:8px">Back to sign in →</a>
  </div>
</div>

<script>
const API = '{APP_URL}';
let _token = '';
let _installCmd = '';

async function doSignup(){{
  const email = document.getElementById('email').value.trim();
  const pwd   = document.getElementById('pwd').value;
  const err   = document.getElementById('err');
  const btn   = document.getElementById('btn');
  err.style.display = 'none';
  if(!email || pwd.length < 8){{ err.textContent = 'Email and password (min 8 chars) required.'; err.style.display='block'; return; }}
  btn.disabled = true; btn.textContent = 'Creating…';
  try{{
    const r = await fetch(API+'/v1/auth/signup', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{email, password: pwd}})
    }});
    const d = await r.json();
    if(!r.ok){{ err.textContent = d.detail || 'Signup failed.'; err.style.display='block'; btn.disabled=false; btn.textContent='Create account'; return; }}
    const st = d.session_token;
    // register agent
    const ar = await fetch(API+'/v1/agents/register', {{
      method:'POST', headers:{{'Content-Type':'application/json','Authorization':'Bearer '+st}},
      body: JSON.stringify({{name:'main', os: navigator.platform||'unknown', version:'1.0.0'}})
    }});
    const ad = await ar.json();
    _token = ad.agent_token || '';
    _installCmd = `curl -sSL ${{API}}/install.sh | bash -s -- --token=${{_token}}`;
    document.getElementById('tok-display').textContent = _token;
    document.getElementById('install-cmd').textContent = _installCmd;
    document.getElementById('form-wrap').style.display = 'none';
    const s = document.getElementById('success');
    s.style.display = 'flex';
  }} catch(e){{
    err.textContent = 'Network error: '+e.message; err.style.display='block';
    btn.disabled=false; btn.textContent='Create account';
  }}
}}

function copyToken(){{
  navigator.clipboard.writeText(_token).catch(()=>{{}});
}}
function copyInstall(){{
  navigator.clipboard.writeText(_installCmd).catch(()=>{{}});
}}

document.getElementById('pwd').addEventListener('keydown', e=>{{ if(e.key==='Enter') doSignup(); }});
</script>
</body></html>"""


# ── login / account page ─────────────────────────────────────────────────
_LOGIN_HTML = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HUNTR — Sign in</title>{_CSS}</head>
<body>
<div class="orbs"><div class="orb orb1"></div><div class="orb orb2"></div></div>
<div class="card" id="card">
  <div class="logo">HUNTR<span>.</span></div>

  <!-- login form -->
  <div id="form-wrap">
    <h1>Sign in</h1>
    <p class="sub">Access your account and agent tokens.</p>
    <div class="err" id="err"></div>
    <label>Email</label>
    <input type="email" id="email" placeholder="you@example.com" autocomplete="email">
    <label>Password</label>
    <input type="password" id="pwd" placeholder="••••••••" autocomplete="current-password">
    <button class="btn" id="btn" onclick="doLogin()">Sign in</button>
    <div class="foot">No account? <a href="/signup">Create one free</a></div>
  </div>

  <!-- account panel -->
  <div id="account" style="display:none">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px">
      <div class="logo" style="margin:0">HUNTR<span>.</span></div>
      <button onclick="doLogout()" style="background:none;border:1px solid var(--border2);border-radius:7px;padding:5px 12px;font-size:12px;color:var(--text3);cursor:pointer">Sign out</button>
    </div>
    <div id="plan-strip" style="background:var(--accent2);border:1px solid rgba(167,139,250,0.2);border-radius:10px;padding:12px 16px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between">
      <span style="font-size:13px;color:var(--text2)">Plan: <strong id="plan-name" style="color:var(--accent)">Free</strong></span>
      <a href="{APP_URL}/v1/billing/portal" id="billing-link" style="font-size:12px;color:var(--text3);text-decoration:none" onclick="openPortal(event)">Manage billing ↗</a>
    </div>
    <div style="font-size:12px;color:var(--text3);margin-bottom:10px;font-weight:600;letter-spacing:0.05em;text-transform:uppercase">Your agents</div>
    <div id="agents-list"></div>
    <button class="btn" style="margin-top:16px" onclick="newAgent()">+ New agent token</button>
  </div>
</div>

<script>
const API = '{APP_URL}';
let _session = '';

async function doLogin(){{
  const email = document.getElementById('email').value.trim();
  const pwd   = document.getElementById('pwd').value;
  const err   = document.getElementById('err');
  const btn   = document.getElementById('btn');
  err.style.display='none';
  btn.disabled=true; btn.textContent='Signing in…';
  try{{
    const r = await fetch(API+'/v1/auth/login', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{email, password: pwd}})
    }});
    const d = await r.json();
    if(!r.ok){{ err.textContent=d.detail||'Login failed.'; err.style.display='block'; btn.disabled=false; btn.textContent='Sign in'; return; }}
    _session = d.session_token;
    try{{ localStorage.setItem('huntr_session', _session); }}catch(e){{}}
    showAccount(d.plan);
  }} catch(e){{ err.textContent='Network error: '+e.message; err.style.display='block'; btn.disabled=false; btn.textContent='Sign in'; }}
}}

async function showAccount(plan){{
  document.getElementById('form-wrap').style.display='none';
  document.getElementById('account').style.display='block';
  document.getElementById('plan-name').textContent = plan==='team'?'Team':plan==='pro'?'Pro':'Free';
  document.getElementById('plan-name').style.color = plan==='free'?'var(--text3)':plan==='pro'?'var(--accent)':'var(--gold)';
  const r = await fetch(API+'/v1/agents/', {{headers:{{'Authorization':'Bearer '+_session}}}});
  const d = await r.json();
  const list = document.getElementById('agents-list');
  if(!d.agents||!d.agents.length){{ list.innerHTML='<div style="font-size:13px;color:var(--text3);padding:12px 0">No agents yet.</div>'; return; }}
  list.innerHTML = d.agents.map(a=>`
    <div style="background:rgba(0,0,0,0.3);border:1px solid var(--border);border-radius:9px;padding:12px 14px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:13px;font-weight:600">${{a.name}}</div>
        <div style="font-size:11px;font-family:var(--mono);color:var(--text3)">${{a.os||'unknown'}} · last seen ${{a.last_seen?new Date(a.last_seen).toLocaleDateString():'never'}}</div>
      </div>
      <button onclick="revokeAgent('${{a.id}}')" style="background:none;border:1px solid rgba(251,113,133,0.2);border-radius:6px;padding:4px 10px;font-size:11px;color:var(--red);cursor:pointer">Revoke</button>
    </div>`).join('');
}}

async function newAgent(){{
  const name = prompt('Agent name (e.g. kali-main):','kali-'+Math.random().toString(36).slice(2,6));
  if(!name) return;
  const r = await fetch(API+'/v1/agents/register', {{
    method:'POST', headers:{{'Content-Type':'application/json','Authorization':'Bearer '+_session}},
    body: JSON.stringify({{name, os: navigator.platform||'unknown', version:'1.0.0'}})
  }});
  const d = await r.json();
  if(d.agent_token){{
    const cmd = `curl -sSL ${{API}}/install.sh | bash -s -- --token=${{d.agent_token}}`;
    alert('New agent token (copy now, shown once):\\n\\n' + d.agent_token + '\\n\\nInstall command:\\n' + cmd);
    showAccount('');
  }}
}}

async function revokeAgent(id){{
  if(!confirm('Revoke this agent? It will stop syncing.')) return;
  await fetch(API+'/v1/agents/'+id, {{method:'DELETE', headers:{{'Authorization':'Bearer '+_session}}}});
  showAccount('');
}}

async function openPortal(e){{
  e.preventDefault();
  const r = await fetch(API+'/v1/billing/portal', {{headers:{{'Authorization':'Bearer '+_session}}}});
  if(r.ok){{ const d=await r.json(); window.open(d.portal_url,'_blank'); }}
  else alert('Billing portal not available on Free plan.');
}}

function doLogout(){{
  _session='';
  try{{localStorage.removeItem('huntr_session');}}catch(e){{}}
  document.getElementById('account').style.display='none';
  document.getElementById('form-wrap').style.display='block';
  document.getElementById('btn').disabled=false;
  document.getElementById('btn').textContent='Sign in';
}}

// auto-restore session
try{{
  const s = localStorage.getItem('huntr_session');
  if(s){{ _session=s; fetch(API+'/v1/billing/status',{{headers:{{'Authorization':'Bearer '+s}}}}).then(r=>r.json()).then(d=>showAccount(d.plan||'free')).catch(()=>{{}}); }}
}}catch(e){{}}

document.getElementById('pwd').addEventListener('keydown', e=>{{ if(e.key==='Enter') doLogin(); }});
</script>
</body></html>"""


# ── install script ────────────────────────────────────────────────────────
_INSTALL_SH = f"""#!/usr/bin/env bash
# HUNTR Agent Installer
# Usage: curl -sSL {APP_URL}/install.sh | bash -s -- --token=YOUR_TOKEN
set -e

HUNTR_TOKEN=""
HUNTR_URL="{APP_URL}"
INSTALL_DIR="$HOME/.huntr-agent"
CONFIG_DIR="$HOME/.huntr"
REPO_URL="https://github.com/HATRIX-x/HUNTR.git"
REPO_BRANCH="tier4-5-tools"

# ── parse args ────────────────────────────────────────────────────────────
for i in "$@"; do
  case $i in
    --token=*)  HUNTR_TOKEN="${{i#*=}}" ;;
    --url=*)    HUNTR_URL="${{i#*=}}" ;;
    --dir=*)    INSTALL_DIR="${{i#*=}}" ;;
  esac
done

if [ -z "$HUNTR_TOKEN" ]; then
  echo "Error: --token=YOUR_AGENT_TOKEN is required."
  echo "Get your token at $HUNTR_URL/signup"
  exit 1
fi

echo ""
echo "  HUNTR Agent Installer"
echo "  ─────────────────────"
echo ""

# ── check Python ──────────────────────────────────────────────────────────
PYTHON=$(command -v python3 || command -v python || true)
if [ -z "$PYTHON" ]; then
  echo "Error: Python 3 not found. Install it first: https://python.org"
  exit 1
fi
PY_VER=$($PYTHON -c "import sys; print(sys.version_info.minor)")
if [ "$PY_VER" -lt 10 ]; then
  echo "Error: Python 3.10+ required (found $($PYTHON --version))"
  exit 1
fi
echo "  ✓ Python: $($PYTHON --version)"

# ── check git ─────────────────────────────────────────────────────────────
if ! command -v git &>/dev/null; then
  echo "Error: git not found. Install it first."
  exit 1
fi
echo "  ✓ git: $(git --version | head -1)"

# ── clone / update repo ───────────────────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
  echo "  ↻ Updating existing install at $INSTALL_DIR …"
  git -C "$INSTALL_DIR" pull --ff-only origin "$REPO_BRANCH" 2>/dev/null || true
else
  echo "  ↓ Cloning HUNTR to $INSTALL_DIR …"
  git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi
echo "  ✓ Agent code ready"

# ── install Python deps ───────────────────────────────────────────────────
echo "  ↓ Installing Python dependencies …"
$PYTHON -m pip install --quiet --user requests 2>/dev/null || true
echo "  ✓ Dependencies installed"

# ── write config ──────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR/logs"
cat > "$CONFIG_DIR/config.json" <<JSON
{{
  "agent_token": "$HUNTR_TOKEN",
  "cloud_url": "$HUNTR_URL",
  "agent_id": null
}}
JSON
echo "  ✓ Config written to $CONFIG_DIR/config.json"

# ── install background service ────────────────────────────────────────────
AGENT_SCRIPT="$INSTALL_DIR/huntr-server.py"
if [ -f "$AGENT_SCRIPT" ]; then
  echo "  ↓ Installing background service …"
  $PYTHON "$INSTALL_DIR/tools/service.py" install 2>/dev/null || true
  echo "  ✓ Service installed (starts on login)"
fi

echo ""
echo "  ────────────────────────────────"
echo "  ✓ HUNTR is ready!"
echo ""
echo "  Start now:  $PYTHON $INSTALL_DIR/huntr-server.py"
echo "  Dashboard:  http://127.0.0.1:8899"
echo "  Cloud:      $HUNTR_URL"
echo "  ────────────────────────────────"
echo ""
"""


# ── routes ────────────────────────────────────────────────────────────────

@router.get("/signup", response_class=HTMLResponse, include_in_schema=False)
def signup_page():
    return _SIGNUP_HTML


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page():
    return _LOGIN_HTML


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def root_redirect():
    return HTMLResponse(
        '<meta http-equiv="refresh" content="0;url=/signup">',
        status_code=200,
    )


@router.get("/install.sh", response_class=PlainTextResponse, include_in_schema=False)
def install_script():
    return PlainTextResponse(_INSTALL_SH, media_type="text/x-shellscript")
