#!/usr/bin/env python3
"""
sync — push findings and funnel events to the HUNTR cloud.

Never blocks a hunt. If the cloud is unreachable, events are queued in
~/.huntr/sync_queue.jsonl and retried on next call.

Usage (from other tools):
    import sys; sys.path.insert(0, str(Path(__file__).parent))
    import sync
    sync.push_finding(finding_dict, program="acme")
    sync.push_funnel(finding_id="F1", stage="confirmed", amount=None)
    sync.flush_queue()          # retry any queued events

CLI (agent calls this directly):
    sync.py --finding-file f.json [--program acme]
    sync.py --funnel-finding-id F1 --funnel-stage confirmed [--amount 500]
    sync.py --flush                   # drain the offline queue
    sync.py --status                  # show queue length + last sync time
"""
import sys, os, json, time, ssl
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

_TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TOOLS))

try:
    from cloud_config import load as _load_cfg, QUEUE_FILE, CONFIG_DIR
except ImportError:
    # inline fallback so sync.py works standalone
    CONFIG_DIR  = Path.home() / ".huntr"
    QUEUE_FILE  = CONFIG_DIR / "sync_queue.jsonl"
    def _load_cfg():
        f = CONFIG_DIR / "config.json"
        return json.loads(f.read_text()) if f.exists() else {}


LAST_SYNC_FILE = CONFIG_DIR / "last_sync.json"
TIMEOUT        = 10   # seconds per request
MAX_QUEUE      = 1000 # drop oldest if queue grows beyond this


# ── internal helpers ────────────────────────────────────────────────────

def _cfg():
    return _load_cfg()


def _headers(token):
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "HUNTR-Agent/1.0",
    }


def _ssl():
    ctx = ssl.create_default_context()
    return ctx


def _post(path, payload):
    cfg   = _cfg()
    token = cfg.get("agent_token")
    base  = cfg.get("cloud_url", "").rstrip("/")
    if not token or not base:
        return {"ok": False, "error": "not configured — run: huntr config set-token <token>"}

    body = json.dumps(payload).encode()
    req  = Request(f"{base}{path}", data=body, headers=_headers(token), method="POST")
    try:
        with urlopen(req, context=_ssl(), timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        msg = e.read().decode()[:200]
        return {"ok": False, "error": f"HTTP {e.code}: {msg}"}
    except (URLError, OSError) as e:
        return {"ok": False, "error": f"unreachable: {e}", "offline": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _enqueue(event: dict):
    CONFIG_DIR.mkdir(exist_ok=True)
    lines = QUEUE_FILE.read_text().splitlines() if QUEUE_FILE.exists() else []
    if len(lines) >= MAX_QUEUE:
        lines = lines[-(MAX_QUEUE - 1):]   # drop oldest
    lines.append(json.dumps(event))
    QUEUE_FILE.write_text("\n".join(lines) + "\n")


def _mark_synced():
    CONFIG_DIR.mkdir(exist_ok=True)
    LAST_SYNC_FILE.write_text(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S")}))


# ── public API ──────────────────────────────────────────────────────────

def push_finding(finding: dict, program: str = "") -> dict:
    """
    Push a confirmed finding to cloud. Queues offline if unreachable.
    finding must contain at minimum: id, class/attack, endpoint, severity, verdict.
    """
    payload = {
        "type":      "finding",
        "ts":        time.strftime("%Y-%m-%d %H:%M:%S"),
        "program":   program or finding.get("program", ""),
        "finding": {
            "id":            finding.get("id") or finding.get("fid", ""),
            "cls":           finding.get("class") or finding.get("attack") or finding.get("category", ""),
            "endpoint":      finding.get("endpoint", ""),
            "severity":      finding.get("severity") or finding.get("estimated_severity", "medium"),
            "title":         finding.get("title", ""),
            "verdict":       finding.get("verdict", ""),
            "dup_prob":      finding.get("dup_prob"),
            "evidence_ref":  finding.get("id") or finding.get("evidence_id", ""),
            "report_score":  finding.get("report_score"),
            "created_at":    finding.get("ts") or time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    }
    result = _post("/v1/sync/finding", payload)
    if result.get("offline"):
        _enqueue(payload)
        return {"ok": False, "queued": True, "error": result["error"]}
    if result.get("ok"):
        _mark_synced()
    return result


def push_funnel(finding_id: str, stage: str, amount=None, program: str = "") -> dict:
    """
    Push a funnel stage transition (flagged → confirmed → submitted → accepted → paid).
    """
    payload = {
        "type":       "funnel",
        "ts":         time.strftime("%Y-%m-%d %H:%M:%S"),
        "finding_id": finding_id,
        "stage":      stage,
        "amount":     amount,
        "program":    program,
    }
    result = _post("/v1/sync/funnel", payload)
    if result.get("offline"):
        _enqueue(payload)
        return {"ok": False, "queued": True, "error": result["error"]}
    if result.get("ok"):
        _mark_synced()
    return result


def flush_queue() -> dict:
    """Retry all queued events. Returns {sent, failed, remaining}."""
    if not QUEUE_FILE.exists():
        return {"sent": 0, "failed": 0, "remaining": 0}

    lines = [l for l in QUEUE_FILE.read_text().splitlines() if l.strip()]
    if not lines:
        return {"sent": 0, "failed": 0, "remaining": 0}

    sent = failed = 0
    remaining = []
    for line in lines:
        try:
            event = json.loads(line)
        except Exception:
            continue
        path = "/v1/sync/finding" if event.get("type") == "finding" else "/v1/sync/funnel"
        result = _post(path, event)
        if result.get("ok"):
            sent += 1
        elif result.get("offline"):
            remaining.append(line)
            failed += 1
        else:
            failed += 1   # server rejected — don't retry

    if remaining:
        QUEUE_FILE.write_text("\n".join(remaining) + "\n")
    else:
        QUEUE_FILE.unlink(missing_ok=True)

    if sent:
        _mark_synced()

    return {"sent": sent, "failed": failed, "remaining": len(remaining)}


# ── CLI ─────────────────────────────────────────────────────────────────

def arg(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default

def flag(name):
    return name in sys.argv


def main():
    if flag("--flush"):
        r = flush_queue()
        print(f"flush: sent={r['sent']} failed={r['failed']} remaining={r['remaining']}")
        return

    if flag("--status"):
        lines = QUEUE_FILE.read_text().splitlines() if QUEUE_FILE.exists() else []
        last  = json.loads(LAST_SYNC_FILE.read_text()).get("ts", "never") if LAST_SYNC_FILE.exists() else "never"
        print(f"Queue: {len([l for l in lines if l.strip()])} pending")
        print(f"Last sync: {last}")
        cfg = _cfg()
        print(f"Configured: {'yes' if cfg.get('agent_token') and cfg.get('cloud_url') else 'no'}")
        return

    if flag("--finding-file"):
        ff = arg("--finding-file")
        if not ff or not Path(ff).exists():
            print("--finding-file path does not exist"); sys.exit(1)
        finding = json.loads(Path(ff).read_text())
        program = arg("--program", finding.get("program", ""))
        r = push_finding(finding, program=program)
        print(json.dumps(r))
        sys.exit(0 if r.get("ok") or r.get("queued") else 1)

    if flag("--funnel-finding-id"):
        fid   = arg("--funnel-finding-id")
        stage = arg("--funnel-stage", "confirmed")
        amount_raw = arg("--amount")
        amount = float(amount_raw) if amount_raw else None
        r = push_funnel(fid, stage, amount=amount, program=arg("--program", ""))
        print(json.dumps(r))
        sys.exit(0 if r.get("ok") or r.get("queued") else 1)

    print(__doc__)


if __name__ == "__main__":
    main()
