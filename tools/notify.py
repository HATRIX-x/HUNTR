#!/usr/bin/env python3
"""
notify — push an event to a webhook (Slack / Discord / generic JSON) so passive
monitoring turns into "you get pinged when there's money on the table": a new
endpoint in a JS diff, a scope/reward change, a confirmed high-severity finding.

Webhook URL resolution (first found):
  --url  ·  $HUNTR_WEBHOOK  ·  <config>/webhook.txt
Format auto-detected from the URL (hooks.slack.com → Slack, discord.com → Discord),
or forced with --format {slack|discord|json}.

config = $HUNTR_CONFIG or ~/.claude/huntr

Usage:
  notify.py --title "New endpoint" --text "POST /api/v2/refunds appeared" \
            [--severity high] [--link https://…] [--format slack] [--json]
  notify.py --set-webhook https://hooks.slack.com/services/…     (saves it)
Exit: 0 sent · 1 no webhook / send failed.
"""
import sys, os, json, time, ssl
from pathlib import Path
from urllib.request import Request, urlopen

CONFIG = Path(os.environ.get("HUNTR_CONFIG", str(Path.home() / ".claude" / "huntr")))
WEBHOOK_FILE = CONFIG / "webhook.txt"

EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d
def flag(n):
    return n in sys.argv


def resolve_webhook(explicit):
    if explicit:
        return explicit
    if os.environ.get("HUNTR_WEBHOOK"):
        return os.environ["HUNTR_WEBHOOK"]
    if WEBHOOK_FILE.exists():
        return WEBHOOK_FILE.read_text().strip()
    return None


def detect_format(url, forced):
    if forced:
        return forced
    if "hooks.slack.com" in url:
        return "slack"
    if "discord.com" in url or "discordapp.com" in url:
        return "discord"
    return "json"


def payload_for(fmt, title, text, severity, link):
    tag = EMOJI.get(severity, "•")
    heading = f"{tag} *{title}*" if severity else f"*{title}*"
    line = f"{heading}\n{text}" + (f"\n{link}" if link else "")
    if fmt == "slack":
        return {"text": line,
                "blocks": [{"type": "section",
                            "text": {"type": "mrkdwn", "text": line}}]}
    if fmt == "discord":
        return {"content": f"{tag} **{title}**\n{text}" + (f"\n{link}" if link else "")}
    return {"title": title, "text": text, "severity": severity, "link": link,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S")}


def send(url, payload):
    req = Request(url, data=json.dumps(payload).encode(),
                  headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
        return r.status, r.read(500).decode("utf-8", "ignore")


def main():
    if arg("--set-webhook"):
        CONFIG.mkdir(parents=True, exist_ok=True)
        WEBHOOK_FILE.write_text(arg("--set-webhook").strip())
        print(json.dumps({"ok": True, "saved": str(WEBHOOK_FILE)}) if flag("--json")
              else f"webhook saved → {WEBHOOK_FILE}")
        sys.exit(0)

    title = arg("--title", "HUNTR")
    text = arg("--text", "")
    severity = (arg("--severity", "") or "").lower()
    link = arg("--link", "")
    url = resolve_webhook(arg("--url"))

    if not url:
        out = {"ok": False, "error": "no webhook (use --set-webhook, $HUNTR_WEBHOOK, or --url)"}
        print(json.dumps(out) if flag("--json") else out["error"])
        sys.exit(1)

    fmt = detect_format(url, arg("--format"))
    payload = payload_for(fmt, title, text, severity, link)
    try:
        status, body = send(url, payload)
        ok = 200 <= status < 300
        out = {"ok": ok, "format": fmt, "status": status,
               "response": body[:200], "ts": time.strftime("%Y-%m-%d %H:%M")}
    except Exception as ex:
        out = {"ok": False, "format": fmt, "error": f"{type(ex).__name__}: {str(ex)[:150]}"}

    if flag("--json"):
        print(json.dumps(out))
        sys.exit(0 if out["ok"] else 1)

    print(f"[notify] {fmt} → {'sent' if out['ok'] else 'FAILED'}"
          + (f" ({out.get('error','')})" if not out["ok"] else f" (HTTP {out['status']})"))
    sys.exit(0 if out["ok"] else 1)


if __name__ == "__main__":
    main()
