#!/usr/bin/env python3
"""
huntr-build-ui — regenerate the local UI (huntr-ui.html) from the premium dashboard.

Keeps the UI and the live bridge DECOUPLED: this writes huntr-ui.html as the dashboard page only.
The engine bridge (huntr-bridge.js) is injected by huntr-server at runtime, so rebuilding the UI can
never drift from or clobber the bridge. Edit the bridge in huntr-bridge.js; edit the UI in the
dashboard; run this to refresh.

Usage:  huntr-build-ui.py --from /path/to/huntr-dashboard.html
"""
import sys
from pathlib import Path

TOOLS = Path.home() / ".claude" / "tools"
SKELETON = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
            '<meta name="color-scheme" content="dark"></head><body>\n')


def arg(n, d=None):
    return sys.argv[sys.argv.index(n) + 1] if n in sys.argv else d


def main():
    src = arg("--from")
    if not src or not Path(src).exists():
        sys.exit("usage: huntr-build-ui.py --from /path/to/huntr-dashboard.html")
    dash = Path(src).read_text()
    (TOOLS / "huntr-ui.html").write_text(SKELETON + dash + "\n</body></html>\n")
    has_bridge = (TOOLS / "huntr-bridge.js").exists()
    print(f"[build-ui] huntr-ui.html rebuilt from {src} (dashboard-only).")
    print(f"[build-ui] bridge {'present' if has_bridge else 'MISSING'} at huntr-bridge.js — server injects it at /.")


if __name__ == "__main__":
    main()
