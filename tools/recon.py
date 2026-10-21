#!/usr/bin/env python3
"""recon.py — clean, resumable recon primitive.

Does ONE thing: given a list of web assets, resolve them to a deduped,
probed, scope-filtered host list. No global STATE, no log()/stage()/flush()
side effects, no silent `except Exception: pass`.

Design (this is the pattern every HUNTR tool should move to):
  - Every failure is CLASSIFIED (timeout / binary-missing / parse-error /
    network-error / denied) and reported in `errors`, never swallowed.
  - Progress is checkpointed to --state after each asset, so a kill/crash
    mid-run resumes instead of restarting. Re-running with the same --state
    file skips assets already resolved.
  - stdout carries exactly one line: the final JSON result. stderr carries
    human-readable progress (so a caller can stream status without having
    to parse JSON until the end, and parsing stdout is never ambiguous).
  - Exit code is a second, redundant signal: 0 = produced a usable host
    list (even if some assets errored), 2 = produced nothing usable.

This script makes no judgment calls about what to do about a failure
(retry? skip? abort the hunt?) — that decision belongs to the orchestrator
calling it (a human, or Claude Code driving the hunt), which is why those
decisions were never reliable when buried in hunt-run.py's except blocks.
"""
import argparse
import fnmatch
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


# ---------- classified subprocess / network helpers (no silent swallowing) ----------

def sh(cmd, timeout=120):
    """Run a command. Returns (stdout, stderr, returncode, error_kind|None)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode, None
    except subprocess.TimeoutExpired:
        return "", "", -1, "timeout"
    except FileNotFoundError:
        return "", "", -1, "binary-missing"
    except Exception as e:
        return "", str(e), -1, "exec-error"


def has(binname):
    from shutil import which
    return which(binname) is not None


def probe_host(host, timeout=8):
    """Probe a single host (https then http).

    Returns (status|None, title, scheme, error_kind|None). error_kind is set
    only when BOTH schemes failed to connect at all — an HTTP error code
    (404, 403, ...) is a successful probe, not a failure.
    """
    last_kind = None
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                scheme + "://" + host, method="GET",
                headers={"User-Agent": "Mozilla/5.0 HUNTR-recon"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(4096).decode("utf-8", "ignore")
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                return (getattr(r, "status", 200) or 200), \
                       (m.group(1).strip()[:60] if m else ""), scheme, None
        except urllib.error.HTTPError as e:
            return e.code, "", scheme, None
        except urllib.error.URLError as e:
            last_kind = "dns-or-conn-refused" if "Name or service" in str(e) or "Connection refused" in str(e) else "network-error"
        except TimeoutError:
            last_kind = "timeout"
        except Exception:
            last_kind = "unknown-error"
    return None, "", "https", last_kind


def apex(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def asset_host(a):
    """(host, is_wildcard) from an asset string like '*.b.com', 'https://x/y', 'rpc.c.net'."""
    h = re.sub(r"^https?://", "", (a or "").strip()).split("/")[0].strip().lower()
    wild = h.startswith("*.")
    return (h[2:] if wild else h), wild


# ---------- resumable state ----------

def load_state(path):
    if not path or not Path(path).exists():
        return {"assets_done": {}, "hosts": {}, "errors": [], "warnings": []}
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        # Corrupt state file: don't silently discard progress by pretending
        # it's empty AND don't crash — report it and start a fresh state,
        # but say so loudly so the caller knows history was lost.
        sys.stderr.write("[recon] WARNING: state file unreadable, starting fresh: " + path + "\n")
        return {"assets_done": {}, "hosts": {}, "errors": [], "warnings": [], "_recovered_from_corrupt": True}


def save_state(path, state):
    if not path:
        return
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(path)  # atomic — a crash mid-write never corrupts the real file


# ---------- the actual work ----------

def enumerate_asset(asset, state, no_brute, single_host, enum_timeout):
    """Resolve one asset to candidate hosts. Mutates state['hosts'], appends
    to state['errors'] on failure. Returns True if it added anything useful."""
    host, wild = asset_host(asset)
    if not host:
        state["errors"].append({"asset": asset, "kind": "unparseable-asset"})
        return False

    ap = apex(host)
    do_enum = wild and not single_host

    def add(h, status=None):
        h = (h or "").strip().lower().split("/")[0]
        if h and h not in state["hosts"]:
            state["hosts"][h] = {"host": h, "status": status, "source_asset": asset}

    if not do_enum:
        add(ap if wild else host)
        sys.stderr.write("[recon] " + asset + " -> exact host, no enumeration\n")
        return True

    enum_tool = HERE / "subdomain-enum.py"
    found_any = False
    if enum_tool.exists():
        cmd = [sys.executable, str(enum_tool), "--domain", ap, "--json"]
        if not no_brute:
            cmd.append("--brute")
        out, err, rc, kind = sh(cmd, timeout=enum_timeout)
        if kind:
            state["errors"].append({"asset": asset, "step": "subdomain-enum.py", "kind": kind, "detail": err[:200]})
        elif rc != 0:
            state["errors"].append({"asset": asset, "step": "subdomain-enum.py", "kind": "nonzero-exit", "detail": (err or out)[:200]})
        else:
            try:
                d = json.loads(out.strip().splitlines()[-1])
                for r in d.get("results", []):
                    add(r.get("host"), r.get("status"))
                    found_any = True
                sys.stderr.write("[recon] " + ap + " -> " + str(d.get("total_found", 0)) + " subdomains (subdomain-enum.py)\n")
            except Exception as e:
                state["errors"].append({"asset": asset, "step": "subdomain-enum.py", "kind": "parse-error", "detail": str(e)[:200]})
    elif has("subfinder"):
        out, err, rc, kind = sh(["subfinder", "-d", ap, "-silent"], timeout=enum_timeout)
        if kind:
            state["errors"].append({"asset": asset, "step": "subfinder", "kind": kind, "detail": err[:200]})
        else:
            for s in out.splitlines()[:60]:
                if s.strip():
                    add(s.strip()); found_any = True
            sys.stderr.write("[recon] " + ap + " -> " + str(found_any and "subdomains via subfinder" or "no output") + "\n")
    else:
        state["warnings"].append({"asset": asset, "kind": "no-enum-tool-available", "detail": "neither subdomain-enum.py nor subfinder found"})

    add(ap)  # the apex itself, always
    return True


def probe_pending(state, probe_timeout, max_probes):
    """Probe every host that has no status yet, up to max_probes this call."""
    probed = 0
    for host, h in state["hosts"].items():
        if h.get("status") is not None:
            continue
        if probed >= max_probes:
            break
        probed += 1
        status, title, scheme, kind = probe_host(host, timeout=probe_timeout)
        h["status"] = status
        h["scheme"] = scheme
        if title:
            h["title"] = title
        if status is None and kind:
            state["errors"].append({"host": host, "step": "probe", "kind": kind})
    return probed


def apply_deny(state, deny_file):
    if not deny_file or not Path(deny_file).exists():
        return 0
    try:
        pats = [l.strip() for l in Path(deny_file).read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    except Exception as e:
        state["errors"].append({"step": "scope-deny", "kind": "read-error", "detail": str(e)[:200]})
        return 0
    if not pats:
        return 0
    dropped = [h for h in state["hosts"]
               if any(fnmatch.fnmatch(h, p) or h == p or h.endswith("." + p.lstrip("*.")) for p in pats)]
    for h in dropped:
        del state["hosts"][h]
    return len(dropped)


def main():
    ap_ = argparse.ArgumentParser(description=__doc__)
    ap_.add_argument("--assets", required=True, help="comma-separated web asset list, or @file.txt")
    ap_.add_argument("--single-host", action="store_true", help="force no subdomain enumeration")
    ap_.add_argument("--no-brute", action="store_true")
    ap_.add_argument("--deny-file", default=None, help="scope.deny path to filter against")
    ap_.add_argument("--state", default=None, help="path to resumable state JSON (recommended for long runs)")
    ap_.add_argument("--enum-timeout", type=int, default=360)
    ap_.add_argument("--probe-timeout", type=int, default=8)
    ap_.add_argument("--max-probes", type=int, default=50, help="probes to run THIS invocation (call again to continue)")
    ap_.add_argument("--max-hosts", type=int, default=200)
    args = ap_.parse_args()

    if args.assets.startswith("@"):
        assets = [l.strip() for l in Path(args.assets[1:]).read_text().splitlines() if l.strip()]
    else:
        assets = [a.strip() for a in args.assets.split(",") if a.strip()]

    state = load_state(args.state)
    state.setdefault("assets_done", {})
    state.setdefault("hosts", {})
    state.setdefault("errors", [])
    state.setdefault("warnings", [])

    t0 = time.time()
    for asset in assets:
        if state["assets_done"].get(asset):
            sys.stderr.write("[recon] " + asset + " already resolved (resumed) — skipping\n")
            continue
        enumerate_asset(asset, state, args.no_brute, args.single_host, args.enum_timeout)
        state["assets_done"][asset] = True
        save_state(args.state, state)  # checkpoint after EVERY asset

    probe_pending(state, args.probe_timeout, args.max_probes)
    save_state(args.state, state)

    dropped = apply_deny(state, args.deny_file)
    if dropped:
        sys.stderr.write("[recon] scope-deny dropped " + str(dropped) + " host(s)\n")
    save_state(args.state, state)

    hosts = list(state["hosts"].values())[:args.max_hosts]
    live = [h for h in hosts if h.get("status")]
    unprobed = sum(1 for h in state["hosts"].values() if h.get("status") is None)

    result = {
        "ok": len(hosts) > 0,
        "hosts": hosts,
        "live_count": len(live),
        "total_count": len(hosts),
        "unprobed_remaining": unprobed,  # >0 means: call again with --state to probe more
        "errors": state["errors"],
        "warnings": state["warnings"],
        "elapsed_s": round(time.time() - t0, 1),
    }
    print(json.dumps(result))

    if unprobed:
        sys.stderr.write("[recon] " + str(unprobed) + " host(s) still unprobed — re-run with the same --state to continue\n")

    sys.exit(0 if result["ok"] else 2)


if __name__ == "__main__":
    main()
