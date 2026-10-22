#!/usr/bin/env python3
"""
hunt-chat.py — conversational assistant for the HUNTR dashboard terminal.

Reads {context, message, history} as JSON from stdin, calls Claude via llm_client
(Claude Pro OAuth — never the Anthropic API key directly), prints the reply as JSON.
The operator can ask about the target, findings, exploitability, next tests, reports.

stdin: {"context":{...hunt state...},"message":"...","history":[{"role","text"}...]}
stdout: {"ok":true,"reply":"..."}  |  {"ok":false,"error":"..."}
"""
import sys, json, importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent


def out(d):
    print(json.dumps(d)); sys.exit(0)


try:
    data = json.loads(sys.stdin.read() or "{}")
except Exception:
    out({"ok": False, "error": "bad stdin json"})

msg = (data.get("message") or "").strip()
if not msg:
    out({"ok": False, "error": "empty message"})
ctx = data.get("context", {})
history = data.get("history", []) or []

try:
    spec = importlib.util.spec_from_file_location("llm_client", str(HERE / "llm_client.py"))
    lc = importlib.util.module_from_spec(spec); spec.loader.exec_module(lc)
except Exception as e:
    out({"ok": False, "error": "llm_client import failed: " + str(e)[:140]})

sys_p = (
    "You are HUNTR, an expert bug-bounty assistant embedded in a live hunt dashboard's terminal. "
    "You can see the current hunt's findings and state (JSON below). Help the operator: explain a "
    "finding, judge its real exploitability and severity, propose the next concrete test or payload, "
    "spot chains between findings, and help write the report. Be concise and technical — this is a "
    "terminal, so plain text, short lines, no markdown headers or filler. When you reference a finding, "
    "use its #index. If asked to take an action you cannot perform yourself (re-verify, confirm, dismiss), "
    "tell the operator the exact slash command (e.g. '/verify 2').\n\nHUNT STATE:\n"
    + json.dumps(ctx)[:7000]
)

lines = []
for h in history[-8:]:
    role = h.get("role", "")
    txt = (h.get("text") or "").strip()
    if not txt:
        continue
    lines.append(("Operator: " if role == "user" else "HUNTR: ") + txt)
lines.append("Operator: " + msg)
user = "\n".join(lines)

text = None
for mdl, to in (("claude-sonnet-5-5", 90), ("claude-haiku-5-5", 75)):
    try:
        text, err = lc.call_llm(sys_p, user, model=mdl, provider="anthropic", max_tokens=1200, timeout=to)
    except Exception as e:
        text, err = None, str(e)
    if text:
        break

if not text:
    out({"ok": False, "error": "assistant unavailable: " + str(err or "")[:150]})

out({"ok": True, "reply": text.strip()})
