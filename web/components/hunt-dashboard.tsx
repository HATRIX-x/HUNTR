"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  getToken, me, listHunts, startHunt, getHunt, listHuntFindings, cancelHunt,
  controlHunt, listAllFindings, getHuntArtifacts, ApiError,
  type Hunt, type Me, type HuntFinding, type AllFinding, type HuntArtifacts,
  type GraphNode, type GraphEdge,
} from "@/lib/api";
import { VncViewer } from "@/components/vnc-viewer";
import { LiveOperation } from "@/components/live-operation";
import { CapabilityGraph3D } from "@/components/capability-graph-3d";

type ConsoleView = "ops" | "findings" | "map" | "coverage" | "surface";

/* ── helpers ──────────────────────────────────────────────────────── */

function ago(iso?: string) {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

// Instant, offline hint only — counts host-like tokens and splits on an
// "out of scope" heading. The authoritative in/out/ambiguous classification is
// done by Haiku 5.5 on the worker (tools/scope_ingest.py) before the hunt runs,
// so this stays deliberately rough and never blocks a launch.
function scopeAtAGlance(text: string): { inN: number; outN: number } | null {
  const raw = (text || "").trim();
  if (raw.length < 4) return null;
  const HOST = /(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi;
  const cut = raw.search(/out[\s-]?of[\s-]?scope|exclusion|excluded|not in scope/i);
  const inPart = cut >= 0 ? raw.slice(0, cut) : raw;
  const outPart = cut >= 0 ? raw.slice(cut) : "";
  const count = (s: string) => new Set((s.match(HOST) || []).map((h) => h.toLowerCase())).size;
  const inN = count(inPart);
  if (inN === 0) return null;
  return { inN, outN: count(outPart) };
}

// First in-scope host in a pasted scope page — used as the provisional `target`
// for the API while the worker's triage model (Haiku 5.5) does the authoritative
// in/out-of-scope split and derives the program name server-side.
function firstScopeHost(text: string): string {
  const raw = (text || "").trim();
  const HOST = /(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/i;
  const cut = raw.search(/out[\s-]?of[\s-]?scope|exclusion|excluded|not in scope/i);
  const inPart = cut >= 0 ? raw.slice(0, cut) : raw;
  const m = inPart.match(HOST);
  return m ? m[0].toLowerCase() : "";
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 12 12" fill="none" aria-hidden>
      <path d="M2.5 6.3 5 8.6l4.5-5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* ── live log tail ────────────────────────────────────────────────── */

function LogTail({ huntId, live }: { huntId: string; live: boolean }) {
  const [logs, setLogs] = useState<string[]>([]);
  const boxRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      getHunt(huntId).then((h) => { if (alive) setLogs(h.logs ?? []); }).catch(() => {});
    load();
    if (!live) return () => { alive = false; };
    const t = setInterval(load, 3000);
    return () => { alive = false; clearInterval(t); };
  }, [huntId, live]);
  useEffect(() => {
    if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [logs]);
  if (logs.length === 0) return null;
  return (
    <div className="border-b border-line">
      <div className="flex items-center justify-between px-5 py-2.5">
        <span className="label text-faint">Operator log</span>
        {live ? (
          <span className="flex items-center gap-2 font-mono text-[10.5px] font-semibold uppercase tracking-[0.16em] text-green">
            <span className="live-dot" /> live
          </span>
        ) : (
          <span className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.16em] text-faint">
            <span className="h-1.5 w-1.5 rounded-full bg-faint" /> ended
          </span>
        )}
      </div>
      <div
        ref={boxRef}
        className="codepane max-h-60 overflow-auto px-5 py-4 text-[11.5px] text-muted [counter-reset:ln]"
        aria-live={live ? "polite" : undefined}
      >
        {logs.map((l, i) => (
          <div key={i} className="ln whitespace-pre-wrap">
            <span className={i === logs.length - 1 && live ? "text-fg" : undefined}>{l}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── findings ─────────────────────────────────────────────────────── */

const SEV: Record<string, string> = {
  critical: "crit",
  high: "high",
  medium: "med",
  low: "low",
  info: "info",
};
const SEV_RAIL: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

function FindingDetail({ f }: { f: HuntFinding }) {
  const panes: [string, string][] = [];
  if (f.report) panes.push(["Report", f.report]);
  if (f.poc) panes.push(["PoC", f.poc]);
  if (f.repro || f.detail) panes.push(["Repro", f.repro || f.detail || ""]);
  const [tab, setTab] = useState(0);
  const [copied, setCopied] = useState(false);
  if (panes.length === 0) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(panes[tab][1]);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch { /* clipboard blocked — no-op */ }
  };
  return (
    <div className="enter mt-4 overflow-hidden rounded-[10px] border border-line bg-black/30 shadow-1">
      <div className="flex items-center justify-between pr-2">
        <div className="seg flex-1 border-b-0" role="tablist">
          {panes.map(([label], i) => (
            <button
              key={label}
              type="button"
              role="tab"
              aria-selected={tab === i}
              onClick={() => setTab(i)}
              className="label"
            >
              {label}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={copy}
          className={`label rounded-md px-3 py-1.5 transition-colors ${copied ? "text-green" : "text-muted hover:text-fg"}`}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <div className="grad-rule opacity-60" />
      <pre className="codepane max-h-[28rem] overflow-auto whitespace-pre-wrap p-5 [counter-reset:ln]">
        {panes[tab][1].split("\n").map((line, i) => (
          <span key={i} className="ln">{line || " "}</span>
        ))}
      </pre>
    </div>
  );
}

function FindingsList({ huntId }: { huntId: string }) {
  const [items, setItems] = useState<HuntFinding[] | null>(null);
  const [err, setErr] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  useEffect(() => {
    let live = true;
    listHuntFindings(huntId)
      .then((r) => { if (live) setItems(r.findings ?? []); })
      .catch(() => { if (live) setErr(true); });
    return () => { live = false; };
  }, [huntId]);
  if (err) return <p className="px-5 py-6 text-sm text-muted">Couldn&apos;t load findings. Reopen the hunt to retry.</p>;
  if (items === null)
    return (
      <div className="space-y-2 px-5 py-5" aria-label="Loading findings">
        {[0, 1].map((i) => <div key={i} className="skeleton h-10" />)}
      </div>
    );
  if (items.length === 0)
    return <p className="px-5 py-6 text-sm text-muted">No findings yet. Validated findings appear here as the hunt confirms them.</p>;
  const verified = items.filter((f) => f.poc_verified).length;
  return (
    <div>
      <div className="flex items-center justify-between px-5 pb-1 pt-4">
        <span className="label text-faint">Findings</span>
        <span className="font-mono text-[11px] text-muted">
          <span className="text-fg">{items.length}</span> reported
          {verified > 0 && <> · <span className="text-green">{verified} verified</span></>}
        </span>
      </div>
      <ul className="divide-y divide-line">
        {items.map((f, i) => {
          const sev = f.severity?.toLowerCase();
          const isOpen = open === i;
          return (
            <li key={i} className="relative">
              <span
                className="absolute bottom-3 left-0 top-3 w-[2px] rounded-full"
                style={{ background: SEV_RAIL[sev] ?? "var(--line-2)", opacity: isOpen ? 1 : 0.6 }}
                aria-hidden
              />
              <div className="px-5 py-4">
                <button
                  type="button"
                  onClick={() => setOpen(isOpen ? null : i)}
                  aria-expanded={isOpen}
                  className="group flex w-full flex-wrap items-start gap-x-3 gap-y-2 text-left sm:flex-nowrap"
                >
                  <span className={`chip mt-0.5 ${SEV[sev] ?? "info"}`}>{f.severity}</span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium leading-snug text-fg transition-colors group-hover:text-brand-200">{f.title}</p>
                    <p className="mt-1 truncate font-mono text-[11px] text-muted">
                      {f.cls} <span className="text-faint">→</span> {f.endpoint}
                    </p>
                  </div>
                  <div className="flex basis-full flex-wrap items-center gap-2.5 pl-[4.6rem] sm:basis-auto sm:shrink-0 sm:pl-0">
                    {f.bounty_est ? (
                      <span className="font-mono text-xs font-semibold text-green tabular">~${f.bounty_est.toLocaleString()}</span>
                    ) : null}
                    {typeof f.cvss === "number" && (
                      <span className="font-mono text-[11px] text-muted tabular">CVSS {f.cvss.toFixed(1)}</span>
                    )}
                    {f.poc_verified ? (
                      <span className="verified"><CheckIcon /> verified</span>
                    ) : f.verdict ? (
                      <span className="chip info">{f.verdict}</span>
                    ) : null}
                  </div>
                </button>
                {isOpen && <FindingDetail f={f} />}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/* ── hunts ────────────────────────────────────────────────────────── */

const MODES = [
  { v: "grey", label: "Grey-box", hint: "with creds" },
  { v: "black", label: "Black-box", hint: "no creds" },
  { v: "white", label: "White-box", hint: "full access" },
];

// running + done share green (the product doing / having done its job) and
// differ by motion: running pulses + glows, done is settled.
const STATUS: Record<string, { label: string; cls: string; rail: string; live?: boolean }> = {
  queued: { label: "Queued", cls: "text-muted", rail: "var(--faint)" },
  running: { label: "Running", cls: "text-green is-live", rail: "var(--green)", live: true },
  paused: { label: "Paused", cls: "text-high", rail: "var(--high)" },
  done: { label: "Done", cls: "text-green", rail: "var(--green-600)" },
  blocked: { label: "Out of credits", cls: "text-high", rail: "var(--high)" },
  error: { label: "Error", cls: "text-critical", rail: "var(--critical)" },
  cancelled: { label: "Cancelled", cls: "text-faint", rail: "var(--line-2)" },
};

function StatusPill({ s }: { s: string }) {
  const st = STATUS[s] ?? { label: s, cls: "text-muted" };
  return (
    <span className={`statuspill ${st.cls}`}>
      {st.live ? <span className="live-dot !h-1.5 !w-1.5" /> : <span className="dot" />}
      {st.label}
    </span>
  );
}

function HuntRow({ h, onWatch, onCancel, onControl }: {
  h: Hunt;
  onWatch: (id: string) => void;
  onCancel: (id: string) => void;
  onControl: (id: string, action: "pause" | "resume") => void;
}) {
  const [open, setOpen] = useState(false);
  const running = h.status === "running";
  const paused = h.status === "paused";
  const st = STATUS[h.status];
  const pct = Math.max(3, Math.min(100, h.pct ?? 0));
  return (
    <div
      className={`panel enter overflow-hidden transition-[border-color,box-shadow] duration-500 ${running ? "is-live" : ""}`}
      style={{ ["--rail" as string]: st?.rail ?? "var(--line-2)" }}
    >
      <span className="rail" aria-hidden />
      <div
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={(e) => { if (e.key === "Enter") setOpen((o) => !o); }}
        className="flex cursor-pointer flex-col gap-4 p-5 transition-colors duration-200 hover:bg-white/[0.015] sm:flex-row sm:items-center sm:justify-between sm:p-6"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3">
            <svg
              viewBox="0 0 12 12"
              className={`h-3 w-3 shrink-0 transition-transform duration-300 ease-out ${open ? "rotate-90 text-brand" : "text-faint"}`}
              aria-hidden
            >
              <path d="M4 2.5 8 6l-4 3.5" stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span className="truncate font-mono text-[15px] font-medium text-fg">{h.target}</span>
            <span className="chip info hidden sm:inline">{h.mode}</span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 pl-6 font-mono text-[11px] text-faint">
            {h.program && <span className="text-muted">{h.program}</span>}
            <span>{ago(h.created_at)}</span>
            <span className="sm:hidden">{h.mode}</span>
          </div>
          {(running || paused) && (
            <div className="mt-3.5 max-w-md pl-6">
              <div className={`progress ${running ? "live" : ""}`}>
                <i style={{ width: `${pct}%`, ["--track" as string]: `${(100 / pct) * 100}%`, filter: paused ? "grayscale(0.6)" : undefined }} />
              </div>
              <p className="mt-2 flex items-center justify-between font-mono text-[11px] text-muted">
                <span className="truncate">{paused ? "paused" : (h.stage || "working…")}</span>
                <span className={`ml-3 tabular ${paused ? "text-high" : "text-green"}`}>{h.pct ?? 0}%</span>
              </p>
            </div>
          )}
          {h.status === "error" && h.error && <p className="mt-2 pl-6 text-xs text-critical">{h.error}</p>}
          {h.status === "blocked" && (
            <p className="mt-2 pl-6 text-xs text-high">
              Paused for credits. <Link href="/account/" onClick={(e) => e.stopPropagation()} className="ulink text-fg">Top up</Link> to resume.
            </p>
          )}
        </div>
        <div className="flex items-center gap-4 pl-6 sm:shrink-0 sm:gap-5 sm:pl-0">
          {running && h.vnc && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onWatch(h.hunt_id); }}
              className="btn-live btn-sm"
            >
              <span className="live-dot" /> Watch live
            </button>
          )}
          {running && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onControl(h.hunt_id, "pause"); }}
              className="label text-faint transition-colors hover:text-high"
              title="Pause this hunt"
            >
              Pause
            </button>
          )}
          {paused && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onControl(h.hunt_id, "resume"); }}
              className="btn-live btn-sm"
              title="Resume this hunt"
            >
              Resume
            </button>
          )}
          {(running || paused || h.status === "queued") && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onCancel(h.hunt_id); }}
              className="label text-faint transition-colors hover:text-critical"
            >
              Cancel
            </button>
          )}
          <div className="min-w-[3.5rem] text-right">
            <p className={`numeral text-2xl ${h.findings > 0 ? "text-green" : "text-fg/60"}`}>{h.findings}</p>
            <p className="label mt-0.5 text-[9.5px] text-faint" title={running || paused ? "Candidate findings the engine is still validating — confirmed ones move to the Findings tab when the hunt finishes." : "Validated findings — see the Findings tab for full reports."}>{running || paused ? "candidates" : "findings"}</p>
          </div>
          <StatusPill s={h.status} />
        </div>
      </div>
      {open && (
        <div className="enter border-t border-line bg-bg/50">
          <LogTail huntId={h.hunt_id} live={running} />
          <FindingsList huntId={h.hunt_id} />
        </div>
      )}
    </div>
  );
}

/* ── telemetry summary ────────────────────────────────────────────── */

function Telemetry({ hunts }: { hunts: Hunt[] }) {
  const running = hunts.filter((h) => h.status === "running").length;
  const queued = hunts.filter((h) => h.status === "queued").length;
  const findings = hunts.reduce((n, h) => n + (h.findings || 0), 0);
  const done = hunts.filter((h) => h.status === "done").length;
  const cells: { k: string; v: number; tone: string; live?: boolean }[] = [
    { k: "Running", v: running, tone: running ? "text-green" : "text-fg/60", live: running > 0 },
    { k: "Queued", v: queued, tone: "text-fg/80" },
    { k: "Completed", v: done, tone: done ? "text-green" : "text-fg/60" },
    { k: "Findings", v: findings, tone: findings ? "text-green" : "text-fg/60" },
  ];
  return (
    <div className="panel grid grid-cols-2 sm:grid-cols-4">
      {cells.map((c, i) => (
        <div
          key={c.k}
          className={`px-5 py-4 sm:px-6 sm:py-5 ${i % 2 ? "border-l border-line" : ""} ${i >= 2 ? "border-t border-line sm:border-t-0" : ""} ${i === 2 ? "sm:border-l" : ""}`}
        >
          <p className="label flex items-center gap-2 text-[10px] text-faint">
            {c.live && <span className="live-dot !h-1.5 !w-1.5" />}
            {c.k}
          </p>
          <p className={`numeral mt-2 text-3xl transition-colors duration-500 ${c.tone}`}>{c.v}</p>
        </div>
      ))}
    </div>
  );
}

/* ── console navigation ───────────────────────────────────────────── */

const NAV: { id: ConsoleView; label: string; icon: React.ReactNode }[] = [
  { id: "ops", label: "Ops", icon: (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden><path d="M3 13h4l2 5 4-12 2 7h6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
  )},
  { id: "findings", label: "Findings", icon: (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden><path d="M6 3h9l5 5v13H6z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" /><path d="M14 3v6h6M9 13h6M9 17h6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
  )},
  { id: "map", label: "Map", icon: (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden><circle cx="12" cy="6" r="2.4" stroke="currentColor" strokeWidth="1.6" /><circle cx="5.5" cy="18" r="2.4" stroke="currentColor" strokeWidth="1.6" /><circle cx="18.5" cy="18" r="2.4" stroke="currentColor" strokeWidth="1.6" /><path d="M10.6 7.8 6.9 15.9M13.4 7.8l3.7 8.1M8 18h8" stroke="currentColor" strokeWidth="1.5" /></svg>
  )},
  { id: "coverage", label: "Coverage", icon: (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden><rect x="3.5" y="3.5" width="7" height="7" rx="1.2" stroke="currentColor" strokeWidth="1.6" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.2" stroke="currentColor" strokeWidth="1.6" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.2" stroke="currentColor" strokeWidth="1.6" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.2" stroke="currentColor" strokeWidth="1.6" /></svg>
  )},
  { id: "surface", label: "Surface", icon: (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" /><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" stroke="currentColor" strokeWidth="1.4" /></svg>
  )},
];

function Sidebar({ view, setView, liveCount }: { view: ConsoleView; setView: (v: ConsoleView) => void; liveCount: number }) {
  return (
    <nav
      aria-label="Console sections"
      className="panel z-10 flex gap-1 overflow-x-auto p-1.5 lg:sticky lg:top-20 lg:h-max lg:flex-col lg:gap-1.5 lg:overflow-visible lg:p-2"
    >
      {NAV.map((n) => {
        const on = view === n.id;
        return (
          <button
            key={n.id}
            type="button"
            onClick={() => setView(n.id)}
            aria-current={on ? "page" : undefined}
            className={`group relative flex shrink-0 flex-col items-center gap-1.5 rounded-[9px] px-4 py-2.5 transition-all duration-200 lg:w-full lg:px-1 ${
              on ? "bg-brand/12 text-fg shadow-[inset_0_0_0_1px_var(--brand-a40)]" : "text-muted hover:bg-white/[0.03] hover:text-fg"
            }`}
          >
            <span className={`h-5 w-5 transition-colors ${on ? "text-brand" : "text-muted group-hover:text-fg"}`}>{n.icon}</span>
            <span className="label text-[9.5px] !tracking-[0.14em]">{n.label}</span>
            {n.id === "ops" && liveCount > 0 && (
              <span className="absolute right-2 top-2 lg:right-3"><span className="live-dot !h-1.5 !w-1.5" /></span>
            )}
            {on && <span className="absolute inset-x-3 -bottom-px hidden h-0.5 rounded bg-grad-brand lg:block" aria-hidden />}
          </button>
        );
      })}
    </nav>
  );
}

/* ── per-hunt artifact loader + hunt picker (Surface / Coverage / Map) ── */

function useArtifacts(huntId: string | null, live: boolean) {
  const [art, setArt] = useState<HuntArtifacts | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  useEffect(() => {
    if (!huntId) { setArt(null); setState("idle"); return; }
    let alive = true;
    setState((s) => (s === "ready" ? s : "loading"));
    const load = () =>
      getHuntArtifacts(huntId)
        .then((a) => { if (alive) { setArt(a); setState("ready"); } })
        .catch(() => { if (alive) setState("error"); });
    load();
    if (!live) return () => { alive = false; };
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, [huntId, live]);
  return { art, state };
}

function HuntPicker({ hunts, sel, setSel }: { hunts: Hunt[]; sel: string | null; setSel: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const cur = hunts.find((h) => h.hunt_id === sel) ?? hunts[0] ?? null;

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    setActive(Math.max(0, hunts.findIndex((h) => h.hunt_id === sel)));
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open, hunts, sel]);

  useEffect(() => {
    if (open && listRef.current) {
      const el = listRef.current.children[active] as HTMLElement | undefined;
      el?.scrollIntoView({ block: "nearest" });
    }
  }, [open, active]);

  if (hunts.length === 0 || !cur) return null;

  const label = (h: Hunt) =>
    `${h.target} · ${STATUS[h.status]?.label ?? h.status}${h.findings ? ` · ${h.findings} finding${h.findings === 1 ? "" : "s"}` : ""}`;

  const choose = (i: number) => { const h = hunts[i]; if (h) { setSel(h.hunt_id); setOpen(false); } };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); if (!open) setOpen(true); else setActive((a) => Math.min(hunts.length - 1, a + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); if (open) setActive((a) => Math.max(0, a - 1)); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); if (open) choose(active); else setOpen(true); }
    else if (e.key === "Escape") { setOpen(false); }
    else if (e.key === "Home") { if (open) { e.preventDefault(); setActive(0); } }
    else if (e.key === "End") { if (open) { e.preventDefault(); setActive(hunts.length - 1); } }
  };

  return (
    <div ref={ref} className="flex items-center gap-3">
      <span className="label text-faint">Hunt</span>
      <div className="relative">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          onKeyDown={onKey}
          aria-haspopup="listbox"
          aria-expanded={open}
          className="hunt-picker group flex min-w-[15rem] max-w-sm items-center gap-2.5 rounded-[9px] border border-line-2 bg-surface2/80 px-3 py-2 text-left transition-colors hover:border-brand/50"
        >
          <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: STATUS[cur.status]?.rail ?? "var(--faint)" }} />
          <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-fg">{label(cur)}</span>
          <svg viewBox="0 0 16 16" className={`h-3.5 w-3.5 shrink-0 text-faint transition-transform duration-200 ${open ? "rotate-180 text-brand" : "group-hover:text-muted"}`} fill="none" aria-hidden>
            <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
        {open && (
          <ul
            ref={listRef}
            role="listbox"
            tabIndex={-1}
            aria-label="Select hunt"
            onKeyDown={onKey}
            className="hunt-pop enter absolute right-0 z-40 mt-2 max-h-72 w-[min(22rem,80vw)] overflow-auto rounded-[11px] border border-line-2 bg-surface2/98 p-1.5 shadow-2 backdrop-blur"
          >
            {hunts.map((h, i) => {
              const on = h.hunt_id === cur.hunt_id;
              const st = STATUS[h.status];
              return (
                <li
                  key={h.hunt_id}
                  role="option"
                  aria-selected={on}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(i)}
                  className={`flex cursor-pointer items-center gap-2.5 rounded-[7px] px-2.5 py-2 ${i === active ? "bg-brand/12" : ""}`}
                >
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: st?.rail ?? "var(--faint)" }} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-[12.5px] text-fg">{h.target}</span>
                    <span className={`block truncate text-[11px] ${st?.cls ?? "text-faint"}`}>
                      {st?.label ?? h.status}{h.findings ? ` · ${h.findings} finding${h.findings === 1 ? "" : "s"}` : ""}
                    </span>
                  </span>
                  {on && (
                    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5 shrink-0 text-brand" fill="none" aria-hidden>
                      <path d="M3.5 8.5 6.5 11.5 12.5 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function ViewHeader({ title, sub, right }: { title: string; sub: string; right?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h2 className="display text-2xl text-fg sm:text-3xl">{title}</h2>
        <p className="mt-1.5 max-w-xl text-sm text-muted">{sub}</p>
      </div>
      {right}
    </div>
  );
}

function EmptyArt({ state, label }: { state: string; label: string }) {
  return (
    <div className="tile-locked flex flex-col items-center px-6 py-14 text-center">
      <p className="label text-brand">{state === "error" ? "Couldn't load" : "Nothing yet"}</p>
      <p className="mt-2 max-w-sm text-sm text-muted">
        {state === "error"
          ? "Reopen the view to retry."
          : `${label} appears here once a hunt has run far enough to produce it.`}
      </p>
    </div>
  );
}

/* ── Findings (all hunts) ─────────────────────────────────────────── */

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function FindingsView() {
  const [items, setItems] = useState<AllFinding[] | null>(null);
  const [err, setErr] = useState(false);
  const [sev, setSev] = useState<string | null>(null);
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  useEffect(() => {
    let alive = true;
    listAllFindings()
      .then((r) => { if (alive) setItems(r.findings ?? []); })
      .catch(() => { if (alive) setErr(true); });
    return () => { alive = false; };
  }, []);
  const counts = tallyFindings(items);
  const shown = (items ?? []).filter((f) =>
    (!sev || (f.severity?.toLowerCase() ?? "info") === sev) && (!verifiedOnly || f.poc_verified));
  return (
    <div className="space-y-6">
      <ViewHeader title="Findings" sub="Every validated finding across your hunts. Verified ones carry a live proof." />
      {items === null && !err && (
        <div className="space-y-2">{[0, 1, 2].map((i) => <div key={i} className="skeleton h-16" />)}</div>
      )}
      {err && <EmptyArt state="error" label="Findings" />}
      {items !== null && items.length === 0 && (
        <div className="tile-locked flex flex-col items-center px-6 py-14 text-center">
          <p className="display text-xl text-fg">No findings yet</p>
          <p className="mt-2 max-w-sm text-sm text-muted">Launch a hunt from Ops. Validated findings land here as they&apos;re confirmed.</p>
        </div>
      )}
      {items !== null && items.length > 0 && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => setSev(null)} className={`chip ${!sev ? "val" : "info"}`}>All {items.length}</button>
            {SEV_ORDER.filter((s) => counts[s]).map((s) => (
              <button key={s} type="button" onClick={() => setSev(sev === s ? null : s)}
                className={`chip ${sev === s ? SEV[s] ?? "info" : "info"}`}>{s} {counts[s]}</button>
            ))}
            <button type="button" onClick={() => setVerifiedOnly((v) => !v)}
              className={`chip ml-auto ${verifiedOnly ? "val" : "info"}`}>✓ verified {counts.verified}</button>
          </div>
          <ul className="space-y-2">
            {shown.map((f, i) => {
              const s = f.severity?.toLowerCase() ?? "info";
              const isOpen = open === i;
              return (
                <li key={i} className="panel overflow-hidden">
                  <button type="button" onClick={() => setOpen(isOpen ? null : i)} aria-expanded={isOpen}
                    className="group flex w-full items-start gap-3 p-4 text-left transition-colors hover:bg-white/[0.015]">
                    <span className={`chip mt-0.5 ${SEV[s] ?? "info"}`}>{f.severity}</span>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium leading-snug text-fg transition-colors group-hover:text-brand-200">{f.title}</p>
                      <p className="mt-1 truncate font-mono text-[11px] text-muted">
                        <span className="text-faint">{f.target}</span> · {f.cls} <span className="text-faint">→</span> {f.endpoint}
                      </p>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1.5 sm:flex-row sm:items-center sm:gap-2.5">
                      {f.bounty_est ? <span className="font-mono text-xs font-semibold text-green tabular">~${f.bounty_est.toLocaleString()}</span> : null}
                      {typeof f.cvss === "number" && <span className="font-mono text-[11px] text-muted tabular">CVSS {f.cvss.toFixed(1)}</span>}
                      {f.poc_verified ? <span className="verified"><CheckIcon /> verified</span> : f.verdict ? <span className="chip info">{f.verdict}</span> : null}
                    </div>
                  </button>
                  {isOpen && <div className="border-t border-line px-4 pb-4"><FindingDetail f={f} /></div>}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}

function tallyFindings(items: AllFinding[] | null) {
  const c: Record<string, number> = { verified: 0 };
  for (const f of items ?? []) {
    const s = f.severity?.toLowerCase() ?? "info";
    c[s] = (c[s] ?? 0) + 1;
    if (f.poc_verified) c.verified += 1;
  }
  return c;
}

/* ── Surface ──────────────────────────────────────────────────────── */

function SurfaceView({ hunts, sel, setSel }: { hunts: Hunt[]; sel: string | null; setSel: (id: string) => void }) {
  const picked = hunts.find((h) => h.hunt_id === sel) ?? null;
  const { art, state } = useArtifacts(sel, picked?.status === "running");
  const s = art?.surface;
  return (
    <div className="space-y-6">
      <ViewHeader title="Surface" sub="The real attack surface HUNTR mapped — hosts, endpoints, and the scope that gates them."
        right={<HuntPicker hunts={hunts} sel={sel} setSel={setSel} />} />
      {!s ? <EmptyArt state={state} label="The surface map" /> : (
        <>
          <div className="panel grid grid-cols-2 sm:grid-cols-4">
            {[["Subdomains", s.stats?.subs], ["Live hosts", s.stats?.live], ["Endpoints", s.stats?.endpoints ?? s.endpoints.length], ["Findings", s.stats?.findings]].map(([k, v], i) => (
              <div key={k as string} className={`px-5 py-4 ${i % 2 ? "border-l border-line" : ""} ${i >= 2 ? "border-t border-line sm:border-t-0" : ""} ${i === 2 ? "sm:border-l" : ""}`}>
                <p className="label text-[10px] text-faint">{k}</p>
                <p className="numeral mt-2 text-3xl text-fg">{Number(v ?? 0)}</p>
              </div>
            ))}
          </div>
          {s.scope && (s.scope.allow?.length || s.scope.deny?.length) ? (
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="panel p-5">
                <p className="label text-green">In scope · {s.scope.allow.length}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {s.scope.allow.slice(0, 80).map((a, i) => <span key={i} className="chip val">{a}</span>)}
                </div>
              </div>
              <div className="panel p-5">
                <p className="label text-critical">Out of scope · {s.scope.deny.length}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {s.scope.deny.length ? s.scope.deny.slice(0, 80).map((a, i) => <span key={i} className="chip crit">{a}</span>) : <span className="text-sm text-muted">None declared.</span>}
                </div>
              </div>
            </div>
          ) : null}
          <div className="panel overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3">
              <p className="label text-faint">Endpoints · {s.endpoints.length}</p>
            </div>
            <div className="max-h-[32rem] overflow-auto border-t border-line">
              <table className="w-full text-left font-mono text-[12px]">
                <tbody className="divide-y divide-line">
                  {s.endpoints.slice(0, 1000).map((e, i) => (
                    <tr key={i} className="hover:bg-white/[0.02]">
                      <td className="w-16 whitespace-nowrap px-5 py-2 text-brand">{e.method || "GET"}</td>
                      <td className="truncate px-2 py-2 text-fg/85">{e.url}</td>
                      {e.src && <td className="whitespace-nowrap px-5 py-2 text-right text-faint">{e.src}</td>}
                    </tr>
                  ))}
                </tbody>
              </table>
              {s.endpoints.length === 0 && <p className="px-5 py-6 text-sm text-muted">No endpoints mapped yet.</p>}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Coverage ─────────────────────────────────────────────────────── */

const COV_COLOR: Record<string, string> = {
  finding: "var(--critical)", tested: "var(--green)", todo: "var(--high)",
  notool: "var(--line-2)", na: "transparent",
};
const COV_LABEL: Record<string, string> = {
  finding: "Finding", tested: "Tested", todo: "To do", notool: "No tool", na: "N/A",
};

function CoverageView({ hunts, sel, setSel }: { hunts: Hunt[]; sel: string | null; setSel: (id: string) => void }) {
  const picked = hunts.find((h) => h.hunt_id === sel) ?? null;
  const { art, state } = useArtifacts(sel, picked?.status === "running");
  const c = art?.coverage;
  return (
    <div className="space-y-6">
      <ViewHeader title="Coverage" sub="Every surface-item × vuln-class cell HUNTR actually tested — the denominator, not a vibe."
        right={<HuntPicker hunts={hunts} sel={sel} setSel={setSel} />} />
      {!c || !c.classes?.length ? <EmptyArt state={state} label="The coverage ledger" /> : (
        <>
          <div className="panel flex flex-wrap items-center gap-6 p-5">
            <div>
              <p className="label text-faint">Cells covered</p>
              <p className="numeral mt-1 text-4xl text-green">{c.pct}%</p>
            </div>
            <div className="min-w-[12rem] flex-1">
              <div className="progress"><i style={{ width: `${c.pct}%` }} /></div>
              <p className="mt-2 font-mono text-[11px] text-muted">{c.tested} tested / {c.total} applicable cells across {c.rows.length} items</p>
            </div>
            <div className="flex flex-wrap gap-3">
              {Object.entries(COV_LABEL).filter(([k]) => k !== "na").map(([k, lbl]) => (
                <span key={k} className="flex items-center gap-1.5 text-[11px] text-muted">
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ background: COV_COLOR[k] }} />{lbl}
                </span>
              ))}
            </div>
          </div>
          <div className="panel overflow-auto">
            <table className="w-full border-collapse text-[11px]">
              <thead>
                <tr>
                  <th className="sticky left-0 z-10 bg-surface2 px-4 py-2 text-left font-mono text-faint">endpoint</th>
                  {c.classes.map((cl) => (
                    <th key={cl} className="px-1 py-2 text-center"><span className="inline-block max-w-[3.2rem] truncate align-bottom font-mono text-[10px] text-muted" title={cl}>{cl}</span></th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {c.rows.slice(0, 400).map((r, i) => (
                  <tr key={i} className="hover:bg-white/[0.02]">
                    <td className="sticky left-0 z-10 max-w-[18rem] truncate bg-surface2 px-4 py-1.5 font-mono text-fg/80" title={r.item}>{r.item}</td>
                    {c.classes.map((cl) => {
                      const st = r.cells[cl] ?? "na";
                      return <td key={cl} className="px-1 py-1.5 text-center" title={`${cl}: ${COV_LABEL[st] ?? st}`}>
                        <span className="mx-auto block h-3.5 w-3.5 rounded-[3px]" style={{ background: COV_COLOR[st] ?? "transparent", border: st === "na" ? "1px solid var(--line)" : "none" }} />
                      </td>;
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Map (capability graph) ───────────────────────────────────────── */

const NODE_COLOR: Record<string, string> = {
  root: "var(--brand)", host: "var(--brand)", target: "var(--brand)",
  endpoint: "var(--green)", finding: "var(--critical)", param: "var(--high)",
};

function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return ""; }
}
function pathOf(url: string): string {
  try { return new URL(url).pathname || url; } catch { return url; }
}

// Build a capability graph from the mapped surface (hosts + endpoints) and the
// hunt's findings, for when the engine didn't emit its own graph.json. Hosts and
// endpoints become nodes (host → endpoint edges); each finding hangs off the
// endpoint it was found on (matched exactly, then by path prefix for templated
// endpoints, then by host). Keeps the Map from ever being blank for a hunt that
// actually mapped a surface.
function synthGraph(
  surface: NonNullable<HuntArtifacts["surface"]> | null | undefined,
  findings: HuntFinding[],
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seen = new Set<string>();
  const add = (id: string, label: string, type: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, label, type });
  };
  const hosts = surface?.hosts ?? [];
  const eps = surface?.endpoints ?? [];
  for (const h of hosts) {
    const hv = h.host ?? "";
    if (hv) add(`host:${hv}`, hv, "host");
  }
  const epIds: { url: string; id: string }[] = [];
  for (const e of eps.slice(0, 300)) {
    const url = e.url ?? "";
    if (!url) continue;
    const hv = e.host || hostOf(url);
    if (hv) add(`host:${hv}`, hv, "host");
    const id = `ep:${url}`;
    add(id, pathOf(url), "endpoint");
    epIds.push({ url, id });
    if (hv) edges.push({ source: `host:${hv}`, target: id });
  }
  findings.forEach((f, i) => {
    const fid = `finding:${i}`;
    add(fid, `${f.cls || "finding"}${f.title ? ` · ${f.title.slice(0, 40)}` : ""}`, "finding");
    const fep = f.endpoint || "";
    let tgt: string | null = null;
    const exact = epIds.find((e) => e.url === fep);
    if (exact) tgt = exact.id;
    if (!tgt && fep) {
      const base = fep.split("{")[0];
      if (base.length > 12) tgt = epIds.find((e) => e.url.startsWith(base))?.id ?? null;
    }
    if (!tgt && fep) {
      const hv = hostOf(fep);
      if (hv && seen.has(`host:${hv}`)) tgt = `host:${hv}`;
    }
    if (!tgt && hosts[0]?.host) tgt = `host:${hosts[0].host}`;
    if (tgt) edges.push({ source: tgt, target: fid });
  });
  const ids = new Set(nodes.map((n) => n.id));
  return {
    nodes: nodes.slice(0, 400),
    edges: edges.filter((e) => ids.has(e.source) && ids.has(e.target)).slice(0, 1000),
  };
}

function MapView({ hunts, sel, setSel }: { hunts: Hunt[]; sel: string | null; setSel: (id: string) => void }) {
  const picked = hunts.find((h) => h.hunt_id === sel) ?? null;
  const { art, state } = useArtifacts(sel, picked?.status === "running");
  // Findings for the selected hunt, overlaid as finding nodes when we synthesize.
  const [findings, setFindings] = useState<HuntFinding[]>([]);
  useEffect(() => {
    let alive = true;
    setFindings([]);
    if (!sel) return;
    listHuntFindings(sel).then((r) => { if (alive) setFindings(r.findings ?? []); }).catch(() => {});
    return () => { alive = false; };
  }, [sel]);
  // Prefer the engine's own graph; otherwise synthesize one from the surface so a
  // hunt that mapped endpoints always has a Map to show.
  const g = useMemo(() => {
    if (art?.graph && art.graph.nodes.length) return art.graph;
    return synthGraph(art?.surface, findings);
  }, [art, findings]);
  return (
    <div className="space-y-6">
      <ViewHeader title="Map" sub="The capability graph in 3D — every host, endpoint and finding a node; every chainable path an edge. Drag to orbit."
        right={<HuntPicker hunts={hunts} sel={sel} setSel={setSel} />} />
      {!g || !g.nodes.length ? <EmptyArt state={state} label="The capability graph" /> : (
        <div className="panel brackets overflow-hidden">
          <div className="scanline">
            <CapabilityGraph3D nodes={g.nodes} edges={g.edges} />
          </div>
          <div className="flex flex-wrap gap-3 border-t border-line px-4 py-3">
            {Object.entries({ host: "Host", endpoint: "Endpoint", finding: "Finding", param: "Param" }).map(([k, lbl]) => (
              <span key={k} className="flex items-center gap-1.5 text-[11px] text-muted">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: NODE_COLOR[k] }} />{lbl}
              </span>
            ))}
            <span className="ml-auto font-mono text-[11px] text-faint">{g.nodes.length} nodes · {g.edges.length} edges</span>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── console ──────────────────────────────────────────────────────── */

export function HuntDashboard() {
  const [state, setState] = useState<"loading" | "ready" | "signedout">("loading");
  const [user, setUser] = useState<Me | null>(null);
  const [hunts, setHunts] = useState<Hunt[]>([]);
  const [mode, setMode] = useState("grey");
  const [scopeText, setScopeText] = useState("");
  const [session, setSession] = useState("");
  const [authHeader, setAuthHeader] = useState("");
  const [ua, setUa] = useState("");
  const [showCreds, setShowCreds] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [watching, setWatching] = useState<string | null>(null);
  const [view, setView] = useState<ConsoleView>("ops");
  const [selHunt, setSelHunt] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const needsCreds = mode === "grey" || mode === "white";
  const scopeStats = scopeAtAGlance(scopeText);

  const credits = user?.credits ?? 0;

  // UI-only: true while the last poll couldn't reach the API, so the console can
  // say so instead of silently showing zeros.
  const [offline, setOffline] = useState(false);

  const refresh = async () => {
    try {
      const { hunts } = await listHunts();
      setHunts(hunts);
      setOffline(false);
    } catch (e) {
      /* transient — keep last list, but tell the user it's stale */
      if (!(e instanceof ApiError && e.status === 401)) setOffline(true);
    }
  };
  const loadUser = () =>
    me().then(setUser).catch((e) => {
      if (e instanceof ApiError && e.status === 401) setState("signedout"); // session expired
    });

  useEffect(() => {
    if (!getToken()) {
      setState("signedout");
      return;
    }
    Promise.all([loadUser(), refresh()]).finally(() => setState((s) => (s === "signedout" ? s : "ready")));
    timer.current = setInterval(refresh, 5000);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, []);

  const onLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    const sp = scopeText.trim();
    if (!sp) {
      setErr("Paste the program's scope page — HUNTR needs it to lock scope.");
      return;
    }
    // Provisional target from the paste; the worker's triage model does the real
    // in/out-of-scope split and names the program server-side.
    const t = firstScopeHost(sp);
    if (!t) {
      setErr("No valid host found in that scope page. Paste the program's in-scope hosts or the whole scope block.");
      return;
    }
    setBusy(true);
    try {
      const creds =
        needsCreds && (session.trim() || authHeader.trim() || ua.trim())
          ? { session: session.trim() || undefined, auth_header: authHeader.trim() || undefined, ua: ua.trim() || undefined }
          : undefined;
      await startHunt({
        target: t,
        mode,
        scope_text: sp,
        creds,
      });
      setScopeText("");
      setSession("");
      setAuthHeader("");
      setUa("");
      await refresh();
      // reflect the spent-credit estimate optimistically
      loadUser();
    } catch (e) {
      if (e instanceof ApiError && e.status === 402) {
        setErr("Not enough credits to start a hunt — top up to run one.");
      } else if (e instanceof ApiError && e.status === 401) {
        setState("signedout");
      } else {
        setErr(e instanceof Error ? e.message : "Couldn't start the hunt.");
      }
    } finally {
      setBusy(false);
    }
  };

  const onControl = async (id: string, action: "pause" | "resume") => {
    // optimistic flip so the UI responds instantly; the 5s poll reconciles
    setHunts((hs) => hs.map((h) => (h.hunt_id === id ? { ...h, status: action === "pause" ? "paused" : "running" } : h)));
    try { await controlHunt(id, action); } catch { /* reconciled by refresh */ }
    refresh();
  };

  if (state === "loading") {
    return (
      <div className="space-y-6" aria-label="Loading console">
        <div className="skeleton h-12 w-64" />
        <div className="skeleton h-24" />
        <div className="skeleton h-72" />
      </div>
    );
  }
  if (state === "signedout") {
    return (
      <div className="panel brackets mx-auto max-w-md px-6 py-10 text-center sm:p-10">
        <div className="icon-badge mx-auto h-14 w-14">
          <svg viewBox="0 0 24 24" className="h-6 w-6 text-brand" fill="none" aria-hidden>
            <rect x="5" y="10.5" width="14" height="10" rx="2" stroke="currentColor" strokeWidth="1.6" />
            <path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3" stroke="currentColor" strokeWidth="1.6" />
          </svg>
        </div>
        <h1 className="display mt-6 text-3xl text-fg">Sign in to hunt</h1>
        <p className="mt-3 text-sm text-muted">The operator console lives behind your account.</p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link href="/login/" className="btn-brand">Sign in</Link>
          <Link href="/signup/" className="btn-outline">Create account</Link>
        </div>
      </div>
    );
  }

  const active = hunts.filter((h) => h.status === "running" || h.status === "queued");

  return (
    <div className="space-y-8">
      {/* header */}
      <div className="flex flex-wrap items-end justify-between gap-5">
        <div>
          <p className="hud flex items-center gap-2 text-[11px] uppercase tracking-[0.18em] text-muted">
            <span className="live-dot" /> operator console
            {user?.email && <span className="hidden text-faint sm:inline">· {user.email}</span>}
          </p>
          <h1 className="display mt-3 text-4xl text-fg sm:text-5xl">Hunt dashboard</h1>
        </div>
        <Link
          href="/account/"
          className="panel group flex items-center gap-5 py-3 pl-5 pr-3 transition-shadow duration-300 hover:shadow-glow-live"
        >
          <span>
            <span className="label block text-[10px] text-faint">Credit balance</span>
            <span className={`numeral mt-1 block text-3xl ${user ? "text-green" : "text-faint"}`}>{user ? credits.toLocaleString() : "—"}</span>
          </span>
          <span className="btn-live btn-sm">Top up</span>
        </Link>
      </div>
      <div className="grad-rule" />

      {offline && (
        <div role="status" className="enter alert alert-error">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden><path d="M12 8v5m0 3.5h.01M10.3 3.9 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <span className="alert-body">Can&apos;t reach HUNTR right now, so this console may be out of date. Retrying every few seconds.</span>
          <button type="button" className="alert-action" onClick={() => { loadUser(); refresh(); }}>Retry now</button>
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[96px_minmax(0,1fr)] lg:gap-7">
        <Sidebar view={view} setView={setView} liveCount={active.length} />
        <div className="min-w-0">
          {view === "ops" && (
            <div className="space-y-8">
              <Telemetry hunts={hunts} />
              {(() => {
                const live = hunts.find((h) => h.status === "running") ?? hunts.find((h) => h.status === "queued");
                return live ? <LiveOperation hunt={live} /> : null;
              })()}

      {/* launch form — arming an operation */}
      <form onSubmit={onLaunch} className="panel brackets overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: "radial-gradient(80% 120% at 0% 0%, var(--brand-a10), transparent 55%)" }}
          aria-hidden
        />
        <div className="relative p-6 sm:p-8">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="display text-2xl text-fg">Launch a hunt</h2>
              <p className="mt-2 max-w-xl text-sm leading-relaxed text-muted">
                HUNTR runs it fully autonomously on our infrastructure. No setup.
                <span className="text-fg"> Authorized targets only.</span>
              </p>
            </div>
            <span className="hud flex items-center gap-1.5 text-[10.5px] uppercase tracking-[0.14em] text-brand">
              <svg viewBox="0 0 12 12" className="h-2.5 w-2.5" aria-hidden><rect x="2" y="5.5" width="8" height="5.5" rx="1" fill="currentColor" /><path d="M4 5.5V4a2 2 0 0 1 4 0v1.5" stroke="currentColor" strokeWidth="1.3" fill="none" /></svg>
              scope-locked
            </span>
          </div>

          {/* ── scope page — the single source of truth for a hunt ──────────
             Paste the program's scope block; the worker's triage model (Haiku
             5.5) names the program and splits in-scope from out-of-scope. */}
          <div className="mt-7">
            <label className="block">
              <span className="field-label flex items-center justify-between gap-3">
                <span>Scope page</span>
                {scopeStats ? (
                  <span className="flex items-center gap-2 font-mono text-[11px] normal-case tracking-normal">
                    <span className="text-green">{scopeStats.inN} in scope</span>
                    {scopeStats.outN > 0 && <span className="text-critical">· {scopeStats.outN} out</span>}
                  </span>
                ) : (
                  <span className="normal-case tracking-normal text-brand/80">required</span>
                )}
              </span>
              <textarea
                required
                value={scopeText}
                onChange={(e) => setScopeText(e.target.value)}
                rows={6}
                spellCheck={false}
                autoComplete="off"
                placeholder={"Paste the program's scope page — hosts, wildcards, or the whole HackerOne / YesWeHack / Bugcrowd scope block.\n\n*.acme.com\nhttps://api.acme.com"}
                className="field resize-y font-mono text-[13px] leading-relaxed"
              />
            </label>
            <p className="mt-2 flex items-start gap-2 text-xs text-muted">
              <svg viewBox="0 0 16 16" className="mt-[1px] h-3.5 w-3.5 shrink-0 text-brand" fill="none" aria-hidden>
                <path d="M8 2.2l1.2 2.9 3.1.2-2.4 2 .8 3-2.7-1.7-2.7 1.7.8-3-2.4-2 3.1-.2z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
              </svg>
              {scopeStats ? (
                <span>
                  <span className="text-green">{scopeStats.inN} in scope</span>
                  {scopeStats.outN > 0 && <> · <span className="text-critical">{scopeStats.outN} out of scope</span></>} detected.
                  <span className="text-faint"> HUNTR&apos;s triage model names the program and re-classifies every asset on the worker before the hunt starts.</span>
                </span>
              ) : (
                <span>HUNTR&apos;s triage model reads this, works out the <span className="text-fg">program name</span>, and sorts <span className="text-green">in-scope</span> from <span className="text-critical">out-of-scope</span> so nothing N/A gets hunted.</span>
              )}
            </p>
          </div>

          <fieldset className="mt-5">
            <legend className="field-label">Mode</legend>
            <div className="grid gap-2 sm:grid-cols-3" role="radiogroup">
              {MODES.map((m) => {
                const sel = mode === m.v;
                return (
                  <button
                    key={m.v}
                    type="button"
                    role="radio"
                    aria-checked={sel}
                    onClick={() => setMode(m.v)}
                    className={`flex items-center justify-between rounded-[7px] border px-4 py-3 text-left transition-all duration-200 ${
                      sel
                        ? "border-brand bg-brand/10 shadow-[0_0_0_4px_var(--brand-a10)]"
                        : "border-line-2 bg-bg/40 hover:border-white/25"
                    }`}
                  >
                    <span>
                      <span className={`block text-sm font-semibold ${sel ? "text-fg" : "text-fg/80"}`}>{m.label}</span>
                      <span className="block text-xs text-muted">{m.hint}</span>
                    </span>
                    <span
                      className={`grid h-4 w-4 place-items-center rounded-full border transition-colors ${sel ? "border-brand" : "border-line-2"}`}
                      aria-hidden
                    >
                      {sel && <span className="h-2 w-2 rounded-full bg-brand" />}
                    </span>
                  </button>
                );
              })}
            </div>
          </fieldset>

          {/* ── credentials / session (grey + white box) ────────────────── */}
          {needsCreds && (
            <div className="mt-3 overflow-hidden rounded-[10px] border border-line bg-bg/30">
              <button
                type="button"
                onClick={() => setShowCreds((v) => !v)}
                aria-expanded={showCreds}
                className="flex w-full items-center justify-between gap-3 px-4 py-3.5 text-left transition-colors hover:bg-white/[0.015]"
              >
                <span className="flex min-w-0 items-center gap-3">
                  <svg viewBox="0 0 16 16" className={`h-3.5 w-3.5 shrink-0 transition-transform duration-300 ${showCreds ? "rotate-90 text-brand" : "text-faint"}`} fill="none" aria-hidden>
                    <path d="M5.5 3.5 10 8l-4.5 4.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  <span className="min-w-0">
                    <span className="block text-sm font-semibold text-fg">Session &amp; credentials <span className="font-normal text-faint">· for {mode}-box</span></span>
                    <span className="block truncate text-xs text-muted">Paste anything from a logged-in browser — HUNTR hunts as an authenticated user.</span>
                  </span>
                </span>
                {(session.trim() || authHeader.trim()) && <span className="verified shrink-0"><CheckIcon /> set</span>}
              </button>
              {showCreds && (
                <div className="enter space-y-4 border-t border-line px-4 py-4">
                  <label className="block">
                    <span className="field-label">Session <span className="normal-case tracking-normal text-faint">· cookie, bearer/JWT, header, Netscape file, or copied cURL</span></span>
                    <textarea
                      value={session}
                      onChange={(e) => setSession(e.target.value)}
                      rows={3}
                      spellCheck={false}
                      autoComplete="off"
                      placeholder="Paste a Cookie header, a bearer token, an X-Auth: … line, a cookies.txt export, or DevTools → Copy as cURL. HUNTR detects which it is."
                      className="field resize-y font-mono text-[12.5px] leading-relaxed"
                    />
                  </label>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <label className="block">
                      <span className="field-label">Extra auth header <span className="normal-case tracking-normal text-faint">· optional</span></span>
                      <input value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} spellCheck={false} autoComplete="off" placeholder="X-Api-Key: …" className="field font-mono text-[13px]" />
                    </label>
                    <label className="block">
                      <span className="field-label">User-Agent suffix <span className="normal-case tracking-normal text-faint">· optional</span></span>
                      <input value={ua} onChange={(e) => setUa(e.target.value)} spellCheck={false} autoComplete="off" placeholder="e.g. program-required tag" className="field font-mono text-[13px]" />
                    </label>
                  </div>
                  <p className="flex items-start gap-2 text-xs text-muted">
                    <svg viewBox="0 0 16 16" className="mt-0.5 h-3.5 w-3.5 shrink-0 text-green" fill="none" aria-hidden><rect x="3.5" y="7" width="9" height="6.5" rx="1.5" stroke="currentColor" strokeWidth="1.3" /><path d="M5.5 7V5.3a2.5 2.5 0 0 1 5 0V7" stroke="currentColor" strokeWidth="1.3" /></svg>
                    Sent once to launch this hunt and never stored on your account. Black-box ignores credentials entirely.
                  </p>
                </div>
              )}
            </div>
          )}

          {err && (
            <div role="alert" className="enter alert alert-error mt-6">
              <svg viewBox="0 0 24 24" fill="none" aria-hidden><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.7" /><path d="M12 7.5v5.5m0 3.5h.01" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" /></svg>
              <span className="alert-body">{err}</span>
              {/credits/i.test(err) && <Link href="/account/" className="alert-action">Top up credits</Link>}
            </div>
          )}
          <div className={`flex flex-col-reverse gap-4 border-t border-line pt-6 sm:flex-row sm:items-center sm:justify-between ${err ? "mt-5" : "mt-7"}`}>
            <p className="text-xs text-muted">
              Findings are validated before they reach you. Nothing is ever auto-submitted.
            </p>
            <button type="submit" disabled={busy} className="btn-grad shrink-0 px-9">
              {busy ? (
                <>
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-bg/30 border-t-bg" aria-hidden />
                  Launching…
                </>
              ) : (
                "Launch hunt"
              )}
            </button>
          </div>
        </div>
      </form>

      {/* hunts — the mission board */}
      <section>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="display text-xl text-fg">Your hunts</h2>
          {active.length > 0 && (
            <span className="statuspill is-live text-green">
              <span className="live-dot !h-1.5 !w-1.5" />
              {active.length} active
            </span>
          )}
        </div>
        {hunts.length === 0 ? (
          <div className="tile-locked flex flex-col items-center px-6 py-14 text-center">
            <svg viewBox="0 0 48 48" className="h-12 w-12 text-brand/70" fill="none" aria-hidden>
              <circle cx="24" cy="24" r="15" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 5" />
              <path d="M24 4v10M24 34v10M4 24h10M34 24h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              <circle cx="24" cy="24" r="3" style={{ fill: "var(--green)" }} />
            </svg>
            <p className="display mt-5 text-xl text-fg">No hunts yet</p>
            <p className="mt-2 max-w-sm text-sm text-muted">Paste a scope page above and launch. Progress, logs and findings stream in here live.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {hunts.map((h) => (
              <HuntRow
                key={h.hunt_id}
                h={h}
                onWatch={setWatching}
                onControl={onControl}
                onCancel={async (id) => { try { await cancelHunt(id); } catch { /* ignore */ } refresh(); }}
              />
            ))}
          </div>
        )}
      </section>
            </div>
          )}

          {view === "findings" && <FindingsView />}
          {view === "surface" && <SurfaceView hunts={hunts} sel={selHunt ?? hunts[0]?.hunt_id ?? null} setSel={setSelHunt} />}
          {view === "coverage" && <CoverageView hunts={hunts} sel={selHunt ?? hunts[0]?.hunt_id ?? null} setSel={setSelHunt} />}
          {view === "map" && <MapView hunts={hunts} sel={selHunt ?? hunts[0]?.hunt_id ?? null} setSel={setSelHunt} />}
        </div>
      </div>

      {watching && <VncViewer huntId={watching} onClose={() => setWatching(null)} />}
    </div>
  );
}
