#!/usr/bin/env python3
"""
oast.py — out-of-band callback via interactsh (real OAST for blind bug proof).

Wraps the installed `interactsh-client`: registers a public callback domain, hands out unique
per-probe URLs, and tells you which probes actually phoned home (DNS/HTTP/SMTP). This is how blind
SSRF / RCE / command-injection / XXE / blind-SSTI get PROVEN against real external targets — the
server makes an outbound request to our interactsh domain, we see the interaction, done.

As a library:
    o = OAST()                       # starts interactsh-client, gets a domain
    if o.ready:
        u = o.url("probe1")          # http://probe1.<rand>.oast.fun
        ... inject u into the payload ...
        hits = o.poll("probe1", wait=8)   # [] or list of interactions
    o.stop()
CLI (self-test): oast.py --selftest
"""
import sys, os, re, json, time, threading, subprocess, shutil, uuid
from pathlib import Path

_DOMAIN_RE = re.compile(r"\b([a-z0-9]+\.(?:oast\.(?:fun|site|live|pro|me|online)|interact\.sh))\b", re.I)


class OAST:
    def __init__(self, timeout_start=12):
        self.ready = False
        self.domain = None
        self.proc = None
        self._lines = []
        self._lock = threading.Lock()
        bin = shutil.which("interactsh-client") or str(Path.home() / "go" / "bin" / "interactsh-client")
        if not Path(bin).exists():
            return
        try:
            self.proc = subprocess.Popen([bin, "-json"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, bufsize=1, errors="replace")
        except Exception:
            self.proc = None
            return
        threading.Thread(target=self._reader, daemon=True).start()
        end = time.time() + timeout_start
        while time.time() < end and not self.domain:
            time.sleep(0.3)
        self.ready = bool(self.domain)

    def _reader(self):
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            if not self.domain:
                m = _DOMAIN_RE.search(line)
                if m:
                    # strip any leading sub-labels → the registration root domain
                    self.domain = m.group(1)
            with self._lock:
                self._lines.append(line)

    def url(self, token):
        token = re.sub(r"[^a-z0-9]", "", (token or uuid.uuid4().hex[:8]).lower())[:20]
        return (f"http://{token}.{self.domain}", token) if self.domain else (None, token)

    def poll(self, token, wait=8):
        if not self.ready:
            return []
        token = re.sub(r"[^a-z0-9]", "", (token or "").lower())[:20]
        end = time.time() + wait
        hits = []
        while time.time() < end:
            with self._lock:
                blob = "".join(self._lines)
            for ln in blob.splitlines():
                if token and token in ln.lower():
                    try:
                        hits.append(json.loads(ln))
                    except Exception:
                        hits.append({"raw": ln[:200]})
            if hits:
                break
            time.sleep(0.8)
        # dedup
        seen, out = set(), []
        for h in hits:
            k = json.dumps(h, sort_keys=True)[:200]
            if k not in seen:
                seen.add(k); out.append(h)
        return out

    def stop(self):
        try:
            if self.proc:
                self.proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        o = OAST()
        print(json.dumps({"ready": o.ready, "domain": o.domain}))
        o.stop()
