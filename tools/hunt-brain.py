#!/usr/bin/env python3
"""
hunt-brain.py — HUNTR self-learning module.

Persists compound intelligence across hunts:
  1. Winning paths   — tool sequences that led to findings
  2. Hit-rate matrix — which vuln classes fire on which stacks
  3. Hunt notes      — post-hunt Haiku-written summaries
  4. FP filters      — patterns that led to false positives
  5. Pattern bank    — cross-hunt repeated patterns → promoted rules
  6. Tool ordering   — which tool types lead to findings fastest
  7. Skill upgrades  — queued proposals to update hunt-* skills

DB: ~/.huntr/brain.db (SQLite, WAL mode for concurrent writes)
"""
import sys, os, json, sqlite3, time, re, argparse
from pathlib import Path

DB_PATH = Path(os.environ.get("HUNTR_HOME", str(Path.home() / ".huntr"))) / "brain.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS winning_paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stack TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    path_json TEXT NOT NULL,
    target TEXT,
    finding_title TEXT,
    created_at REAL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS hit_rates (
    stack TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    hits INTEGER DEFAULT 0,
    last_updated REAL DEFAULT (unixepoch()),
    PRIMARY KEY (stack, vuln_class)
);
CREATE TABLE IF NOT EXISTS hunt_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    stack TEXT,
    note TEXT NOT NULL,
    has_findings INTEGER DEFAULT 0,
    created_at REAL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS fp_patterns (
    pattern TEXT PRIMARY KEY,
    reason TEXT,
    count INTEGER DEFAULT 1,
    last_seen REAL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS cross_patterns (
    pattern TEXT PRIMARY KEY,
    vuln_class TEXT,
    stack TEXT,
    targets_seen TEXT DEFAULT '[]',
    count INTEGER DEFAULT 1,
    promoted INTEGER DEFAULT 0,
    last_seen REAL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS tool_stats (
    tool_name TEXT NOT NULL,
    sequence_pos INTEGER DEFAULT 0,
    led_to_finding INTEGER DEFAULT 0,
    total INTEGER DEFAULT 1,
    PRIMARY KEY (tool_name, led_to_finding)
);
CREATE TABLE IF NOT EXISTS skill_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_class TEXT,
    pattern TEXT,
    evidence TEXT,
    skill_file TEXT,
    applied INTEGER DEFAULT 0,
    created_at REAL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS hunt_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    stack TEXT,
    n_findings INTEGER DEFAULT 0,
    n_actions INTEGER DEFAULT 0,
    duration_sec REAL DEFAULT 0,
    created_at REAL DEFAULT (unixepoch())
);
"""

def _db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn

# ── 1. Winning paths ─────────────────────────────────────────────────────────

def record_winning_path(stack, vuln_class, path, target, title):
    if not stack or not vuln_class or not path:
        return
    path_json = json.dumps(path[-15:]) if isinstance(path, list) else str(path)[:4000]
    with _db() as c:
        c.execute(
            "INSERT INTO winning_paths (stack, vuln_class, path_json, target, finding_title) VALUES (?,?,?,?,?)",
            (stack[:40], vuln_class[:40], path_json, (target or "")[:80], (title or "")[:120])
        )

def get_winning_paths(stack, vuln_class=None, limit=3):
    with _db() as c:
        if vuln_class:
            rows = c.execute(
                "SELECT path_json, finding_title, target FROM winning_paths WHERE stack=? AND vuln_class=? ORDER BY created_at DESC LIMIT ?",
                (stack, vuln_class, limit)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT path_json, finding_title, target FROM winning_paths WHERE stack=? ORDER BY created_at DESC LIMIT ?",
                (stack, limit)
            ).fetchall()
    result = []
    for row in rows:
        try:
            result.append({"path": json.loads(row[0]), "title": row[1], "target": row[2]})
        except Exception:
            pass
    return result

# ── 2. Hit-rate matrix ───────────────────────────────────────────────────────

def record_hit(stack, vuln_class, found):
    if not stack or not vuln_class:
        return
    with _db() as c:
        c.execute(
            "INSERT INTO hit_rates (stack, vuln_class, attempts, hits) VALUES (?,?,1,?) "
            "ON CONFLICT(stack, vuln_class) DO UPDATE SET attempts=attempts+1, hits=hits+?, last_updated=unixepoch()",
            (stack[:40], vuln_class[:40], int(bool(found)), int(bool(found)))
        )

def get_technique_priority(stack):
    with _db() as c:
        rows = c.execute(
            "SELECT vuln_class, hits*1.0/MAX(attempts,1) as rate, hits, attempts "
            "FROM hit_rates WHERE stack=? AND attempts>=2 ORDER BY rate DESC",
            (stack,)
        ).fetchall()
        global_rows = c.execute(
            "SELECT vuln_class, hits*1.0/MAX(attempts,1) as rate, hits, attempts "
            "FROM hit_rates WHERE attempts>=3 ORDER BY rate DESC LIMIT 20"
        ).fetchall()
    seen = set()
    result = []
    for r in rows:
        if r[0] not in seen:
            seen.add(r[0])
            result.append({"cls": r[0], "rate": round(r[1], 3), "hits": r[2], "attempts": r[3], "source": "stack"})
    for r in global_rows:
        if r[0] not in seen:
            seen.add(r[0])
            result.append({"cls": r[0], "rate": round(r[1], 3), "hits": r[2], "attempts": r[3], "source": "global"})
    return result

# ── 3. Hunt notes ────────────────────────────────────────────────────────────

def write_hunt_note(target, stack, note, has_findings=False):
    if not note or len(note) < 20:
        return
    with _db() as c:
        c.execute(
            "INSERT INTO hunt_notes (target, stack, note, has_findings) VALUES (?,?,?,?)",
            ((target or "")[:80], (stack or "")[:40], note[:2000], int(bool(has_findings)))
        )
        c.execute("DELETE FROM hunt_notes WHERE id NOT IN (SELECT id FROM hunt_notes ORDER BY created_at DESC LIMIT 200)")

def read_hunt_notes(stack, target=None, limit=5):
    with _db() as c:
        if target:
            rows = c.execute(
                "SELECT note, target, has_findings, created_at FROM hunt_notes "
                "WHERE stack=? ORDER BY (target=?) DESC, created_at DESC LIMIT ?",
                (stack, target, limit)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT note, target, has_findings, created_at FROM hunt_notes "
                "WHERE stack=? ORDER BY created_at DESC LIMIT ?",
                (stack, limit)
            ).fetchall()
    return [{"note": r[0], "target": r[1], "has_findings": bool(r[2])} for r in rows]

# ── 4. False positive filters ────────────────────────────────────────────────

def record_fp(pattern, reason):
    if not pattern:
        return
    with _db() as c:
        c.execute(
            "INSERT INTO fp_patterns (pattern, reason, count) VALUES (?,?,1) "
            "ON CONFLICT(pattern) DO UPDATE SET count=count+1, last_seen=unixepoch()",
            (pattern[:200], (reason or "")[:200])
        )

def get_fp_filters(limit=30):
    with _db() as c:
        rows = c.execute(
            "SELECT pattern, reason, count FROM fp_patterns ORDER BY count DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [{"pattern": r[0], "reason": r[1], "count": r[2]} for r in rows]

# ── 5. Cross-hunt pattern bank ───────────────────────────────────────────────

def record_pattern(pattern, vuln_class, stack, target):
    if not pattern:
        return
    with _db() as c:
        existing = c.execute("SELECT targets_seen, count FROM cross_patterns WHERE pattern=?", (pattern[:200],)).fetchone()
        if existing:
            targets = json.loads(existing[0] or "[]")
            if target and target not in targets:
                targets.append(target)
            c.execute(
                "UPDATE cross_patterns SET count=count+1, targets_seen=?, last_seen=unixepoch() WHERE pattern=?",
                (json.dumps(targets[-20:]), pattern[:200])
            )
        else:
            c.execute(
                "INSERT INTO cross_patterns (pattern, vuln_class, stack, targets_seen) VALUES (?,?,?,?)",
                (pattern[:200], (vuln_class or "")[:40], (stack or "")[:40], json.dumps([target] if target else []))
            )

def consolidate():
    with _db() as c:
        rows = c.execute(
            "SELECT pattern, vuln_class, stack, targets_seen, count FROM cross_patterns "
            "WHERE count>=3 AND promoted=0 ORDER BY count DESC LIMIT 50"
        ).fetchall()
        upgraded = 0
        for r in rows:
            pattern, vcls, stack, targets_json, count = r
            targets = json.loads(targets_json or "[]")
            if len(set(targets)) < 2:
                continue
            evidence = f"Seen {count}x across {len(set(targets))} targets: {', '.join(list(set(targets))[:4])}"
            skill_file = _vuln_class_to_skill(vcls)
            c.execute(
                "INSERT INTO skill_queue (vuln_class, pattern, evidence, skill_file) VALUES (?,?,?,?)",
                (vcls[:40], pattern[:200], evidence[:400], skill_file)
            )
            c.execute("UPDATE cross_patterns SET promoted=1 WHERE pattern=?", (pattern,))
            upgraded += 1
    return upgraded

def _vuln_class_to_skill(cls):
    cls = (cls or "").lower()
    mapping = {
        "idor": "hunt-idor", "ssrf": "hunt-ssrf", "xss": "hunt-xss", "sqli": "hunt-sqli",
        "ssti": "hunt-ssti", "cors": "hunt-cors", "jwt": "hunt-jwt-crypto", "race": "hunt-race",
        "graphql": "hunt-graphql", "redirect": "hunt-open-redirect", "csrf": "hunt-csrf",
        "auth": "hunt-auth-bypass", "session": "hunt-session", "rce": "hunt-rce",
    }
    for k, v in mapping.items():
        if k in cls:
            return v
    return "hunt-misc"

# ── 6. Tool-call ordering stats ──────────────────────────────────────────────

def record_tool_use(tool_name, led_to_finding):
    with _db() as c:
        c.execute(
            "INSERT INTO tool_stats (tool_name, led_to_finding, total) VALUES (?,?,1) "
            "ON CONFLICT(tool_name, led_to_finding) DO UPDATE SET total=total+1",
            (tool_name[:40], int(bool(led_to_finding)))
        )

def get_tool_order():
    with _db() as c:
        rows = c.execute(
            "SELECT t1.tool_name, t1.total as hits, COALESCE(t2.total,0) as misses "
            "FROM tool_stats t1 LEFT JOIN tool_stats t2 ON t1.tool_name=t2.tool_name AND t2.led_to_finding=0 "
            "WHERE t1.led_to_finding=1 ORDER BY hits DESC"
        ).fetchall()
    return [{"tool": r[0], "hits": r[1], "misses": r[2],
             "rate": round(r[1] / max(r[1] + r[2], 1), 3)} for r in rows]

# ── 7. Skill upgrade queue ───────────────────────────────────────────────────

def get_pending_upgrades(limit=10):
    with _db() as c:
        rows = c.execute(
            "SELECT id, vuln_class, pattern, evidence, skill_file FROM skill_queue WHERE applied=0 ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [{"id": r[0], "cls": r[1], "pattern": r[2], "evidence": r[3], "skill_file": r[4]} for r in rows]

def apply_upgrade(upgrade_id, skill_dir):
    with _db() as c:
        row = c.execute("SELECT vuln_class, pattern, evidence, skill_file FROM skill_queue WHERE id=?", (upgrade_id,)).fetchone()
        if not row:
            return False
        vcls, pattern, evidence, skill_file = row
    skill_path = Path(skill_dir) / f"{skill_file}.md"
    if not skill_path.exists():
        matches = list(Path(skill_dir).parent.rglob(f"{skill_file}.md")) if Path(skill_dir).parent.exists() else []
        skill_path = matches[0] if matches else None
    if skill_path and skill_path.exists():
        append_text = f"\n\n### Auto-learned pattern ({vcls})\n**Pattern:** {pattern}\n**Evidence:** {evidence}\n"
        skill_path.write_text(skill_path.read_text() + append_text)
    with _db() as c:
        c.execute("UPDATE skill_queue SET applied=1 WHERE id=?", (upgrade_id,))
    return True

# ── Hunt log ─────────────────────────────────────────────────────────────────

def log_hunt(target, stack, n_findings, n_actions, duration_sec):
    with _db() as c:
        c.execute(
            "INSERT INTO hunt_log (target, stack, n_findings, n_actions, duration_sec) VALUES (?,?,?,?,?)",
            ((target or "")[:80], (stack or "")[:40], n_findings, n_actions, duration_sec)
        )
        total = c.execute("SELECT COUNT(*) FROM hunt_log").fetchone()[0]
    if total % 10 == 0:
        n = consolidate()
        if n:
            print(f"[brain] consolidated {n} cross-hunt pattern(s) → skill queue")

# ── Status ───────────────────────────────────────────────────────────────────

def status():
    with _db() as c:
        wp = c.execute("SELECT COUNT(*) FROM winning_paths").fetchone()[0]
        hr = c.execute("SELECT SUM(hits), SUM(attempts) FROM hit_rates").fetchone()
        hn = c.execute("SELECT COUNT(*) FROM hunt_notes").fetchone()[0]
        fp = c.execute("SELECT COUNT(*) FROM fp_patterns").fetchone()[0]
        cp = c.execute("SELECT COUNT(*) FROM cross_patterns").fetchone()[0]
        sq = c.execute("SELECT COUNT(*) FROM skill_queue WHERE applied=0").fetchone()[0]
        hl = c.execute("SELECT COUNT(*) FROM hunt_log").fetchone()[0]
    print(json.dumps({
        "winning_paths": wp, "hit_rate_rows": hr[1] or 0,
        "total_hits": hr[0] or 0, "hunt_notes": hn,
        "fp_patterns": fp, "cross_patterns": cp,
        "pending_upgrades": sq, "total_hunts": hl
    }, indent=2))

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record-path", action="store_true")
    ap.add_argument("--record-hit", action="store_true")
    ap.add_argument("--write-note", action="store_true")
    ap.add_argument("--read-notes", action="store_true")
    ap.add_argument("--record-fp", action="store_true")
    ap.add_argument("--get-fp-filters", action="store_true")
    ap.add_argument("--get-priorities", action="store_true")
    ap.add_argument("--get-paths", action="store_true")
    ap.add_argument("--consolidate", action="store_true")
    ap.add_argument("--log-hunt", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--stack", default="")
    ap.add_argument("--cls", default="")
    ap.add_argument("--path-json", default="[]")
    ap.add_argument("--target", default="")
    ap.add_argument("--title", default="")
    ap.add_argument("--found", type=int, default=0)
    ap.add_argument("--note", default="")
    ap.add_argument("--pattern", default="")
    ap.add_argument("--reason", default="")
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--n-findings", type=int, default=0)
    ap.add_argument("--n-actions", type=int, default=0)
    ap.add_argument("--duration", type=float, default=0)
    args = ap.parse_args()

    if args.record_path:
        try:
            path = json.loads(args.path_json)
        except Exception:
            path = []
        record_winning_path(args.stack, args.cls, path, args.target, args.title)
        print("ok")
    elif args.record_hit:
        record_hit(args.stack, args.cls, args.found)
        print("ok")
    elif args.write_note:
        write_hunt_note(args.target, args.stack, args.note, bool(args.n_findings))
        print("ok")
    elif args.read_notes:
        print(json.dumps(read_hunt_notes(args.stack, args.target, args.limit)))
    elif args.record_fp:
        record_fp(args.pattern, args.reason)
        print("ok")
    elif args.get_fp_filters:
        print(json.dumps(get_fp_filters()))
    elif args.get_priorities:
        print(json.dumps(get_technique_priority(args.stack)))
    elif args.get_paths:
        print(json.dumps(get_winning_paths(args.stack, args.cls or None, args.limit)))
    elif args.consolidate:
        n = consolidate()
        print(json.dumps({"consolidated": n}))
    elif args.log_hunt:
        log_hunt(args.target, args.stack, args.n_findings, args.n_actions, args.duration)
        print("ok")
    elif args.status:
        status()
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
