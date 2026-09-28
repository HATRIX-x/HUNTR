#!/usr/bin/env python3
"""
cloud-config — read/write the agent's cloud connection settings.

Config file: ~/.huntr/config.json
  { "agent_token": "...", "cloud_url": "https://huntr.app", "agent_id": "..." }

Usage:
  cloud-config.py --set-token <token>
  cloud-config.py --set-url <url>
  cloud-config.py --show
  cloud-config.py --clear
"""
import sys, os, json
from pathlib import Path

CONFIG_DIR  = Path.home() / ".huntr"
CONFIG_FILE = CONFIG_DIR / "config.json"
QUEUE_FILE  = CONFIG_DIR / "sync_queue.jsonl"   # offline queue


def load() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


def save(cfg: dict):
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def get(key, default=None):
    return load().get(key, default)


def arg(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def flag(name):
    return name in sys.argv


def main():
    cfg = load()

    if flag("--set-token"):
        token = arg("--set-token")
        if not token:
            print("usage: cloud-config.py --set-token <agent_token>"); sys.exit(1)
        cfg["agent_token"] = token
        save(cfg)
        print(f"Agent token saved.")
        return

    if flag("--set-url"):
        url = arg("--set-url")
        if not url:
            print("usage: cloud-config.py --set-url <url>"); sys.exit(1)
        cfg["cloud_url"] = url.rstrip("/")
        save(cfg)
        print(f"Cloud URL set to {cfg['cloud_url']}")
        return

    if flag("--set-agent-id"):
        cfg["agent_id"] = arg("--set-agent-id")
        save(cfg)
        return

    if flag("--clear"):
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
        print("Config cleared.")
        return

    if flag("--show") or not sys.argv[1:]:
        if not cfg:
            print("No config. Run: cloud-config.py --set-token <token>")
            return
        token = cfg.get("agent_token", "")
        masked = token[:8] + "..." + token[-4:] if len(token) > 12 else "(not set)"
        print(f"Cloud URL  : {cfg.get('cloud_url', '(not set)')}")
        print(f"Agent token: {masked}")
        print(f"Agent ID   : {cfg.get('agent_id', '(not registered)')}")
        q = QUEUE_FILE.read_text().strip().splitlines() if QUEUE_FILE.exists() else []
        print(f"Offline queue: {len(q)} item(s) pending sync")
        return

    print(__doc__)


if __name__ == "__main__":
    main()
