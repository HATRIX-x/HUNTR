#!/usr/bin/env python3
"""
service — install/uninstall/start/stop the HUNTR agent as a background service.

On Linux  : systemd user service (~/.config/systemd/user/huntr-agent.service)
On macOS  : launchd user agent   (~/Library/LaunchAgents/app.huntr.agent.plist)
On Windows: not yet supported (run huntr-server.py manually for now)

Usage:
  service.py install     # install + enable + start
  service.py uninstall   # stop + disable + remove
  service.py start
  service.py stop
  service.py restart
  service.py status
  service.py logs        # tail the last 40 lines of the service log
"""
import sys, os, platform, subprocess, textwrap
from pathlib import Path

AGENT_SCRIPT = Path(__file__).resolve().parent.parent / "huntr-server.py"
PYTHON       = sys.executable
LOG_DIR      = Path.home() / ".huntr" / "logs"
LOG_FILE     = LOG_DIR / "agent.log"
SYSTEM       = platform.system()   # Linux | Darwin | Windows


# ── platform helpers ─────────────────────────────────────────────────────

def _systemd_unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / "huntr-agent.service"


def _launchd_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / "app.huntr.agent.plist"


def _systemd_unit() -> str:
    return textwrap.dedent(f"""\
        [Unit]
        Description=HUNTR Agent — local engine bridge
        After=network.target

        [Service]
        ExecStart={PYTHON} {AGENT_SCRIPT}
        Restart=on-failure
        RestartSec=5
        StandardOutput=append:{LOG_FILE}
        StandardError=append:{LOG_FILE}
        Environment=PYTHONUNBUFFERED=1

        [Install]
        WantedBy=default.target
    """)


def _launchd_plist() -> str:
    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>             <string>app.huntr.agent</string>
            <key>ProgramArguments</key>
            <array>
                <string>{PYTHON}</string>
                <string>{AGENT_SCRIPT}</string>
            </array>
            <key>RunAtLoad</key>         <true/>
            <key>KeepAlive</key>         <true/>
            <key>StandardOutPath</key>   <string>{LOG_FILE}</string>
            <key>StandardErrorPath</key> <string>{LOG_FILE}</string>
            <key>EnvironmentVariables</key>
            <dict>
                <key>PYTHONUNBUFFERED</key><string>1</string>
            </dict>
        </dict>
        </plist>
    """)


def _run(cmd: list[str], check=False) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


# ── actions ──────────────────────────────────────────────────────────────

def install():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if SYSTEM == "Linux":
        unit = _systemd_unit_path()
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(_systemd_unit())
        _run(["systemctl", "--user", "daemon-reload"])
        code, out = _run(["systemctl", "--user", "enable", "--now", "huntr-agent"])
        if code == 0:
            print("✓ huntr-agent service installed and started (systemd user)")
        else:
            print(f"✗ systemctl error: {out}")
            print(f"  Unit file written to: {unit}")
            print("  Try: systemctl --user daemon-reload && systemctl --user start huntr-agent")

    elif SYSTEM == "Darwin":
        plist = _launchd_plist_path()
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_text(_launchd_plist())
        code, out = _run(["launchctl", "load", "-w", str(plist)])
        if code == 0:
            print("✓ huntr-agent service installed and started (launchd)")
        else:
            print(f"✗ launchctl error: {out}")
            print(f"  Plist written to: {plist}")

    else:
        print("Windows: run huntr-server.py manually for now.")
        print(f"  {PYTHON} {AGENT_SCRIPT}")
        return

    print(f"  Log: {LOG_FILE}")
    print("  Runs on every login. Stop with: huntr service stop")


def uninstall():
    if SYSTEM == "Linux":
        _run(["systemctl", "--user", "disable", "--now", "huntr-agent"])
        unit = _systemd_unit_path()
        if unit.exists(): unit.unlink()
        _run(["systemctl", "--user", "daemon-reload"])
        print("✓ huntr-agent service removed")

    elif SYSTEM == "Darwin":
        plist = _launchd_plist_path()
        if plist.exists():
            _run(["launchctl", "unload", "-w", str(plist)])
            plist.unlink()
        print("✓ huntr-agent service removed")
    else:
        print("Windows: nothing to uninstall.")


def start():
    if SYSTEM == "Linux":
        code, out = _run(["systemctl", "--user", "start", "huntr-agent"])
    elif SYSTEM == "Darwin":
        code, out = _run(["launchctl", "load", "-w", str(_launchd_plist_path())])
    else:
        print(f"Run manually: {PYTHON} {AGENT_SCRIPT}"); return
    print("✓ started" if code == 0 else f"✗ {out}")


def stop():
    if SYSTEM == "Linux":
        code, out = _run(["systemctl", "--user", "stop", "huntr-agent"])
    elif SYSTEM == "Darwin":
        code, out = _run(["launchctl", "unload", str(_launchd_plist_path())])
    else:
        print("Kill the huntr-server.py process manually."); return
    print("✓ stopped" if code == 0 else f"✗ {out}")


def restart():
    stop(); start()


def status():
    if SYSTEM == "Linux":
        _, out = _run(["systemctl", "--user", "status", "huntr-agent", "--no-pager"])
        print(out or "(not installed)")
    elif SYSTEM == "Darwin":
        _, out = _run(["launchctl", "list", "app.huntr.agent"])
        print(out or "(not installed)")
    else:
        print("Check Task Manager for huntr-server.py")

    # also show if the server is responding
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:8899/health", timeout=2)
        print("Agent API: ✓ responding on :8899")
    except Exception:
        print("Agent API: ✗ not responding on :8899")


def logs():
    if not LOG_FILE.exists():
        print(f"No log file at {LOG_FILE}"); return
    lines = LOG_FILE.read_text().splitlines()
    print("\n".join(lines[-40:]))


# ── CLI ──────────────────────────────────────────────────────────────────

COMMANDS = {
    "install": install, "uninstall": uninstall,
    "start": start,     "stop": stop,
    "restart": restart, "status": status,
    "logs": logs,
}

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    fn  = COMMANDS.get(cmd)
    if not fn:
        print(__doc__)
        sys.exit(0)
    fn()


if __name__ == "__main__":
    main()
