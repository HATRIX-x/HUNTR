"""capability_edges — turn confirmed findings into capability-graph edges.

An LLM can't reliably hold a 5-step chain in its head, and a human rarely types
out the chain that crosses three findings. So don't make them: map every
confirmed finding to an edge that upgrades one capability into another, union
them, and let capability-graph's BFS find the chain by reachability — including
the one nobody wrote down. This is HUNTR's chaining depth: composition, not
guessing.

A finding may tag its own capability transition explicitly
(``{"from": "...", "to": "...", "impact": "c"}``); if it doesn't, we fall back
to a per-class default so even untagged findings participate in a chain.
"""

# class → (from_capability, to_capability, impact)  — best-effort defaults.
# impact: '-' (intermediate) or c/h/m/l on a goal node.
CLASS_DEFAULTS = {
    "sqli":         ("anon",        "db_read",          "-"),
    "nosqli":       ("anon",        "db_read",          "-"),
    "idor":         ("user",        "victim_data",      "h"),
    "bola":         ("user",        "victim_data",      "h"),
    "auth_bypass":  ("anon",        "user_session",     "-"),
    "authbypass":   ("anon",        "user_session",     "-"),
    "mass_assign":  ("user",        "admin_capability", "h"),
    "massassign":   ("user",        "admin_capability", "h"),
    "ssrf":         ("anon",        "internal_reach",   "-"),
    "rce":          ("anon",        "code_exec",        "c"),
    "lfi":          ("anon",        "file_read",        "m"),
    "open_redirect":("anon",        "oauth_code",       "-"),
    "jwt":          ("anon",        "forged_session",   "-"),
}


def _norm(c):
    return (c or "").lower().strip().replace(" ", "").replace("-", "").replace("_", "")


def edge_from_finding(f):
    """Map one finding dict to a capability edge dict, or None if unmappable."""
    cls = _norm(f.get("class") or f.get("cls"))
    endpoint = f.get("endpoint") or f.get("target_endpoint") or ""
    # explicit transition wins over the class default
    frm = f.get("from")
    to = f.get("to")
    impact = f.get("impact")
    if not (frm and to):
        # try the raw class, then a few common aliases collapsed by _norm
        default = CLASS_DEFAULTS.get(cls)
        if default is None:
            return None
        d_frm, d_to, d_impact = default
        frm = frm or d_frm
        to = to or d_to
        impact = impact if impact is not None else d_impact
    prim = f.get("primitive") or (f"{f.get('class') or cls}:{endpoint}" if endpoint else (f.get('class') or cls))
    return {
        "frm": frm, "prim": prim, "to": to,
        "status": (f.get("status") or "proven").lower(),
        "impact": impact if impact not in (None, "") else "-",
        "ev": f.get("evidence") or f.get("ev") or "",
    }


def edges_from_findings(findings):
    """List of edge dicts for all mappable findings (skips the rest)."""
    out = []
    for f in findings or []:
        e = edge_from_finding(f)
        if e:
            out.append(e)
    return out


def to_tsv(edges):
    """Render edges as a capability-graph capabilities.tsv body."""
    lines = ["# from\tprimitive\tto\tstatus\timpact\tevidence"]
    for e in edges:
        lines.append("\t".join([e["frm"], e["prim"], e["to"], e["status"], e["impact"], e["ev"]]))
    return "\n".join(lines) + "\n"
