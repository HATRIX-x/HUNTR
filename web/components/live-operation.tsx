"use client";

/* ──────────────────────────────────────────────────────────────────────────
   LIVE OPERATION — the screen shown the instant a hunt launches and while it runs.

   HERO: the operator browser is framed as a gunsight viewport (corner brackets,
   a settling reticle, scanlines) with the agent's current action projected ON the
   glass as a HUD caption — the stream is the subject, not a dead black rectangle.

   The 7-phase kill-chain runs down the left rail as a *burning fuse*: a single lit
   line that advances phase to phase, each node showing elapsed time and what it
   produced. A cost / token telemetry strip and a findings feed that ticks in give
   the screen ambient life without clutter. Everything but the viewport stays quiet.
   ────────────────────────────────────────────────────────────────────────── */

import { useEffect, useMemo, useRef, useState } from "react";
import {
  getHunt, getHuntArtifacts, listHuntFindings, creditsBalance,
  type Hunt, type HuntArtifacts, type HuntFinding,
} from "@/lib/api";
import { VncViewer, type StreamPhase } from "@/components/vnc-viewer";

/* ── phase model ──────────────────────────────────────────────────────── */

type Phase = { key: string; name: string; intent: string; match: string[]; Icon: () => JSX.Element };

/* ── premium duotone phase glyphs — crisp 1.6 stroke, round joins, a faint
   currentColor fill for depth. Each phase reads distinctly at 18px. ── */
const S = 1.6;
const IcScope = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden strokeLinecap="round" strokeLinejoin="round"><path d="M4 9V6.5A2.5 2.5 0 0 1 6.5 4H9M15 4h2.5A2.5 2.5 0 0 1 20 6.5V9M20 15v2.5a2.5 2.5 0 0 1-2.5 2.5H15M9 20H6.5A2.5 2.5 0 0 1 4 17.5V15" stroke="currentColor" strokeWidth={S} /><circle cx="12" cy="12" r="3" fill="currentColor" fillOpacity=".16" stroke="currentColor" strokeWidth={S} /><circle cx="12" cy="12" r=".7" fill="currentColor" /></svg>);
const IcRadar = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 9 9" stroke="currentColor" strokeWidth={S} /><path d="M12 12 12 3A9 9 0 0 1 20.5 9.1Z" fill="currentColor" fillOpacity=".16" /><path d="M12 12 19.8 6.6" stroke="currentColor" strokeWidth={S} /><circle cx="12" cy="12" r="3.3" stroke="currentColor" strokeWidth="1.4" strokeOpacity=".65" /><circle cx="16.3" cy="8.4" r="1.05" fill="currentColor" /><circle cx="12" cy="12" r=".8" fill="currentColor" /></svg>);
const IcMap = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="3" width="6" height="5" rx="1.4" fill="currentColor" fillOpacity=".15" stroke="currentColor" strokeWidth={S} /><rect x="3" y="16" width="5.6" height="5" rx="1.3" stroke="currentColor" strokeWidth={S} /><rect x="15.4" y="16" width="5.6" height="5" rx="1.3" stroke="currentColor" strokeWidth={S} /><path d="M12 8v3.5M5.8 16v-2.5a1 1 0 0 1 1-1H17a1 1 0 0 1 1 1V16" stroke="currentColor" strokeWidth="1.5" /></svg>);
const IcPlan = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden strokeLinecap="round" strokeLinejoin="round"><path d="M6.8 7.4 10 10.4M17.3 8 13.9 10.7" stroke="currentColor" strokeWidth="1.5" strokeOpacity=".7" /><path d="M15.8 17.1 13.3 13.6" stroke="currentColor" strokeWidth={S} /><circle cx="12" cy="12" r="2.5" fill="currentColor" fillOpacity=".18" stroke="currentColor" strokeWidth={S} /><circle cx="5" cy="6" r="1.9" stroke="currentColor" strokeWidth="1.5" /><circle cx="19" cy="6.8" r="1.9" stroke="currentColor" strokeWidth="1.5" /><circle cx="17" cy="18.6" r="1.9" fill="currentColor" fillOpacity=".18" stroke="currentColor" strokeWidth="1.5" /></svg>);
const IcExploit = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="7.6" stroke="currentColor" strokeWidth={S} /><circle cx="12" cy="12" r="3.1" fill="currentColor" fillOpacity=".18" stroke="currentColor" strokeWidth="1.4" /><path d="M12 1.8v3.4M12 18.8v3.4M1.8 12h3.4M18.8 12h3.4" stroke="currentColor" strokeWidth={S} /><circle cx="12" cy="12" r="1" fill="currentColor" /></svg>);
const IcVerify = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden strokeLinecap="round" strokeLinejoin="round"><path d="M12 2.8l2.1 1.5 2.5-.2.8 2.4 2.2 1.3-.7 2.5.9 2.4-1.9 1.7-.3 2.6-2.6.3-1.6 2-2.4-.9-2.4.9-1.6-2-2.6-.3-.3-2.6-1.9-1.7.9-2.4-.7-2.5 2.2-1.3.8-2.4 2.5.2z" fill="currentColor" fillOpacity=".14" stroke="currentColor" strokeWidth="1.4" /><path d="M8.7 12.1l2.2 2.2 4.4-4.5" stroke="currentColor" strokeWidth="1.7" /></svg>);
const IcCheck = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden><path d="M20 6.5 9.5 17 4.5 12" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" /></svg>);
const IcReport = () => (<svg viewBox="0 0 24 24" fill="none" aria-hidden strokeLinecap="round" strokeLinejoin="round"><path d="M6 3h7l5 5v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z" fill="currentColor" fillOpacity=".12" stroke="currentColor" strokeWidth={S} /><path d="M13 3v4a1 1 0 0 0 1 1h4" stroke="currentColor" strokeWidth="1.5" /><path d="M8 13.5h7M8 16.8h4.5M8 10.2h3" stroke="currentColor" strokeWidth="1.5" /></svg>);

const PHASES: Phase[] = [
  { key: "scope",   name: "Scope lock",     intent: "Locking the authorized target surface", match: ["scope"], Icon: IcScope },
  { key: "recon",   name: "Recon",          intent: "Enumerating hosts, assets and tech",     match: ["recon", "source", "fingerprint", "boot", "mobile"], Icon: IcRadar },
  { key: "surface", name: "Map surface",    intent: "Crawling the app, mapping endpoints",    match: ["surface", "spa", "discover", "capture", "api-test", "auth+spa"], Icon: IcMap },
  { key: "plan",    name: "Model & plan",   intent: "Modeling entities, planning attacks",    match: ["plan", "biz", "model"], Icon: IcPlan },
  { key: "exploit", name: "Exploit",        intent: "Probing endpoints for real bugs",        match: ["exploit", "authed", "hunt", "ai-direct", "llm-led", "oob", "param"], Icon: IcExploit },
  { key: "verify",  name: "Verify & chain", intent: "Proving findings, chaining impact",      match: ["verify", "validate", "judge", "adversarial", "chain", "scenario", "econom"], Icon: IcVerify },
  { key: "report",  name: "Report",         intent: "Triaging and writing up what's real",    match: ["supervisor", "triager", "polish", "report", "done"], Icon: IcReport },
];

function phaseIndex(stage?: string, status?: string): number {
  if (status === "done") return PHASES.length - 1;
  if (status === "queued" || !stage) return 0;
  const s = stage.toLowerCase();
  for (let i = PHASES.length - 1; i >= 0; i--) if (PHASES[i].match.some((k) => s.includes(k))) return i;
  return 0;
}

/* Optional fields the worker may push beyond the base Hunt type. Read defensively
   so the screen lights up when they arrive and stays honest when they don't. */
type Extra = {
  cost_usd?: number; llm_calls?: number;
  phases?: Record<string, { ran?: number; skipped?: number; confirmed?: number; pruned?: number }>;
  attack_flows?: string[];
};
const extra = (h: Hunt): Extra => h as unknown as Extra;

function fmtDur(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

/* ── the one-line result each completed phase leaves behind ─────────────── */
function phaseResult(key: string, h: Hunt, a: HuntArtifacts | null): string {
  const hosts = a?.surface?.hosts?.length ?? 0;
  const endpoints = a?.surface?.endpoints?.length ?? 0;
  const flows = extra(h).attack_flows?.length ?? 0;
  const graphNodes = a?.graph?.nodes?.length ?? 0;
  const n = h.findings || 0;
  const cov = a?.coverage;
  switch (key) {
    case "scope":   return hosts ? `${hosts} host${hosts === 1 ? "" : "s"} authorized` : "authorized";
    case "recon":   return endpoints ? `${hosts || 1} host${(hosts || 1) === 1 ? "" : "s"}, ${endpoints} endpoints` : hosts ? `${hosts} hosts` : "—";
    case "surface": return endpoints ? `${endpoints} endpoints mapped` : "—";
    case "plan":    return graphNodes ? `${graphNodes} entities${flows ? `, ${flows} flows` : ""}` : flows ? `${flows} attack flows` : "modeled";
    case "exploit": return n ? `${n} candidate${n === 1 ? "" : "s"}` : cov ? `${cov.tested}/${cov.total} tested` : "probing";
    case "verify":  return n ? `${n} confirmed` : "verified";
    case "report":  return `${n} finding${n === 1 ? "" : "s"}`;
    default:        return "";
  }
}

/* live, in-progress sub-line for the ACTIVE phase */
function phaseLive(key: string, h: Hunt, a: HuntArtifacts | null): string {
  const hosts = a?.surface?.hosts?.length ?? 0;
  const endpoints = a?.surface?.endpoints?.length ?? 0;
  const n = h.findings || 0;
  const cov = a?.coverage;
  switch (key) {
    case "scope":   return hosts ? `${hosts} host${hosts === 1 ? "" : "s"} in scope` : "verifying authorization";
    case "recon":   return endpoints ? `${hosts || 1} hosts · ${endpoints} endpoints` : "enumerating assets";
    case "surface": return endpoints ? `${endpoints} endpoints · mapping` : "crawling the app";
    case "plan":    return "modeling entities & attack flows";
    case "exploit": return cov ? `${cov.tested}/${cov.total} tested · ${n} candidate${n === 1 ? "" : "s"}` : n ? `${n} candidate${n === 1 ? "" : "s"}` : "probing endpoints";
    case "verify":  return n ? `${n} finding${n === 1 ? "" : "s"} under review` : "proving impact";
    case "report":  return h.status === "done" ? `${n} finding${n === 1 ? "" : "s"}` : "writing up what's real";
    default:        return "";
  }
}

/* ── the burning-fuse kill-chain rail ───────────────────────────────────── */
function KillChain({
  hunt, cur, done, art, elapsed,
}: { hunt: Hunt; cur: number; done: boolean; art: HuntArtifacts | null; elapsed: number[] }) {
  return (
    <ol className="relative" aria-label="Kill chain progress">
      {/* the fuse spine */}
      <span aria-hidden className="absolute left-[18px] top-2 bottom-2 w-px bg-line" />
      <span aria-hidden className="fuse-lit absolute left-[18px] top-2 w-px"
        style={{ height: `calc(${(Math.min(cur, PHASES.length - 1) / (PHASES.length - 1)) * 100}% - 0px)` }} />
      {PHASES.map((p, i) => {
        const state = done || i < cur ? "done" : i === cur ? "active" : "todo";
        const col = state === "done" ? "var(--green)" : state === "active" ? "var(--cyan)" : "var(--faint)";
        const result = state === "active" ? phaseLive(p.key, hunt, art) : state === "done" ? phaseResult(p.key, hunt, art) : "";
        const t = elapsed[i];
        return (
          <li key={p.key} className="relative flex items-start gap-3 py-[7px] pl-0">
            <span className={`relative z-[1] grid h-9 w-9 shrink-0 place-items-center rounded-full border transition-colors ${state === "active" ? "fuse-node-live" : ""}`}
              style={{ color: col, borderColor: `color-mix(in srgb, ${col} 50%, transparent)`, background: state === "todo" ? "var(--bg)" : `color-mix(in srgb, ${col} 13%, var(--bg))` }}>
              <span className="h-[18px] w-[18px]">{state === "done" ? <IcCheck /> : <p.Icon />}</span>
            </span>
            <div className="min-w-0 flex-1 pt-0.5">
              <div className="flex items-baseline justify-between gap-2">
                <span className="truncate text-[13px] font-semibold" style={{ color: state === "todo" ? "var(--faint)" : "var(--fg)" }}>
                  <span className="mr-1.5 font-mono text-[10px] text-faint">{i + 1}</span>{p.name}
                </span>
                {t != null && (
                  <span className="shrink-0 font-mono text-[10px] tabular-nums" style={{ color: state === "active" ? "var(--cyan)" : "var(--faint)" }}>
                    {state === "active" ? fmtDur(t) : fmtDur(t)}
                  </span>
                )}
              </div>
              <p className="mt-0.5 truncate text-[11.5px] leading-tight" style={{ color: state === "active" ? "var(--cyan)" : state === "done" ? "var(--muted)" : "var(--faint)" }}>
                {state === "todo" ? p.intent : result || p.intent}
              </p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/* ── ambient telemetry strip (balance / coverage / pace) ────────────────── */
function Telemetry({ hunt, art, running }: { hunt: Hunt; art: HuntArtifacts | null; running: boolean }) {
  const [credits, setCredits] = useState<number | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () => creditsBalance().then((c) => { if (alive) setCredits(c.balance); }).catch(() => {});
    load();
    if (!running) return () => { alive = false; };
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, [running]);

  const cov = art?.coverage;
  const cells: { k: string; v: string; tone?: string; live?: boolean }[] = [];
  if (credits != null) cells.push({ k: "Credit balance", v: credits.toLocaleString(), tone: "var(--green)" });
  if (cov && cov.total) cells.push({ k: "Coverage", v: `${Math.round((cov.tested / Math.max(1, cov.total)) * 100)}%`, tone: "var(--cyan)" });
  cells.push({ k: running ? "Candidates" : "Findings", v: String(hunt.findings || 0), tone: (hunt.findings || 0) ? "var(--green)" : undefined, live: running });
  if (cells.length === 0) return null;
  return (
    <div className="hud flex flex-wrap items-stretch divide-x divide-line rounded-lg border border-line bg-bg/40">
      {cells.map((c) => (
        <div key={c.k} className="min-w-[72px] flex-1 px-3 py-2">
          <div className="flex items-center gap-1.5 text-[9px] uppercase tracking-[0.14em] text-faint">
            {c.live && <span className="live-dot !h-1.5 !w-1.5" />}{c.k}
          </div>
          <div className="mt-1 font-mono text-[15px] font-semibold tabular-nums" style={{ color: c.tone ?? "var(--fg)" }}>{c.v}</div>
        </div>
      ))}
    </div>
  );
}

/* ── findings feed (ticks in newest-first) ──────────────────────────────── */
const SEV_CHIP: Record<string, string> = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
const SEV_COL: Record<string, string> = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--cyan)" };

function FindingsFeed({ huntId, live, count }: { huntId: string; live: boolean; count: number }) {
  const [items, setItems] = useState<HuntFinding[]>([]);
  useEffect(() => {
    let alive = true;
    const load = () => listHuntFindings(huntId).then((r) => { if (alive) setItems(r.findings ?? []); }).catch(() => {});
    load();
    if (!live) return () => { alive = false; };
    const t = setInterval(load, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [huntId, live]);

  const pending = Math.max(0, count - items.length);
  return (
    <div className="panel flex min-h-0 flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <span className="label text-[10px] text-faint">Findings feed</span>
        <span className="hud flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em]" style={{ color: count ? "var(--green)" : "var(--faint)" }}>
          {live && count > 0 && <span className="live-dot !h-1.5 !w-1.5" />}{count} {live ? "candidate" : "confirmed"}{count === 1 ? "" : "s"}
        </span>
      </div>
      <ul className="min-h-0 flex-1 divide-y divide-line overflow-auto" aria-live={live ? "polite" : undefined}>
        {items.length === 0 && pending === 0 && (
          <li className="px-4 py-6 text-center text-[12px] text-faint">
            {live ? "No candidates yet — HUNTR is still working the surface." : "No findings."}
          </li>
        )}
        {items.map((f, i) => {
          const sev = (f.severity || "info").toLowerCase();
          return (
            <li key={`${f.title}-${i}`} className="feed-row flex items-start gap-3 px-4 py-2.5">
              <span aria-hidden className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: SEV_COL[sev] ?? "var(--cyan)", boxShadow: `0 0 10px -1px ${SEV_COL[sev] ?? "var(--cyan)"}` }} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className={`chip ${SEV_CHIP[sev] ?? "info"}`}>{sev}</span>
                  {f.poc_verified && <span className="chip val">verified</span>}
                  {typeof f.bounty_est === "number" && f.bounty_est > 0 && <span className="font-mono text-[11px] text-green tabular-nums">~${f.bounty_est.toLocaleString()}</span>}
                </div>
                <p className="mt-1 truncate text-[12.5px] text-fg">{f.title}</p>
                {f.endpoint && <p className="truncate font-mono text-[10.5px] text-faint">{f.endpoint}</p>}
              </div>
            </li>
          );
        })}
        {pending > 0 && (
          <li className="feed-row flex items-center gap-3 px-4 py-2.5 text-[11.5px] text-muted">
            <span aria-hidden className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-cyan" />
            {pending} more candidate{pending === 1 ? "" : "s"} being triaged…
          </li>
        )}
      </ul>
    </div>
  );
}


/* ── the hero: operator-browser viewport, framed as a gunsight ──────────── */
function Viewport({ hunt, art }: { hunt: Hunt; art: HuntArtifacts | null }) {
  const [control, setControl] = useState(false);
  const [stream, setStream] = useState<StreamPhase>("loading");
  const [reconnect, setReconnect] = useState(0);
  const [full, setFull] = useState(false);
  const figRef = useRef<HTMLElement>(null);
  const running = hunt.status === "running";

  // Fullscreen the viewport so the operator can actually see/click the page when
  // driving. Uses the native Fullscreen API on the figure (the same noVNC canvas
  // scales up via scaleViewport — no second stream).
  useEffect(() => {
    const onFs = () => setFull(document.fullscreenElement === figRef.current);
    document.addEventListener("fullscreenchange", onFs);
    return () => document.removeEventListener("fullscreenchange", onFs);
  }, []);
  const toggleFull = () => {
    const el = figRef.current;
    if (!el) return;
    if (document.fullscreenElement === el) document.exitFullscreen().catch(() => {});
    else el.requestFullscreen?.().catch(() => {});
  };

  // The agent's current action, projected onto the glass. Prefer the live log tail.
  const action = useMemo(() => {
    const last = (hunt.logs ?? []).map((l) => (l ?? "").trim()).filter(Boolean).slice(-1)[0] ?? "";
    return last;
  }, [hunt.logs]);

  const cur = phaseIndex(hunt.stage, hunt.status);
  const phaseName = PHASES[Math.min(cur, PHASES.length - 1)].name;
  const edge = stream === "lost" ? "var(--faint)" : control ? "var(--high)" : running ? "var(--green)" : "var(--faint)";

  return (
    <figure
      ref={figRef}
      className={`viewport brackets relative overflow-hidden border bg-black ${full ? "flex h-screen w-screen flex-col rounded-none" : "rounded-xl"}`}
      style={{ ["--bracket" as string]: edge, borderColor: `color-mix(in srgb, ${edge} 30%, transparent)` }}
    >
      {/* top rail — what the operator is looking at + control affordance */}
      <figcaption className="relative z-[4] flex items-center justify-between gap-3 border-b border-line bg-surface2/95 px-3.5 py-2">
        <span className="hud flex min-w-0 items-center gap-2 text-[11px] uppercase tracking-[0.15em]">
          {stream === "lost" ? (
            <><span className="h-1.5 w-1.5 rounded-full bg-faint" /><span className="text-faint">signal lost</span></>
          ) : stream === "live" ? (
            control ? (
              <><span className="h-1.5 w-1.5 rounded-full bg-high" /><span className="font-semibold text-high">you have control</span></>
            ) : (
              <><span className="live-dot" /><span className="font-semibold text-green">live</span><span className="truncate text-faint">· HUNTR is driving · {phaseName}</span></>
            )
          ) : (
            <><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan" /><span className="text-muted">connecting…</span></>
          )}
        </span>
        <div className="flex shrink-0 items-center gap-1.5">
          {stream === "live" && running && (
            <button type="button" onClick={() => setControl((c) => !c)}
              className={`label rounded-md px-2.5 py-1 text-[10px] transition-colors ${control ? "bg-high/15 text-high hover:bg-high/25" : "bg-white/5 text-fg hover:bg-white/10"}`}
              title={control ? "Stop sending your input to the hunt's browser" : "Send your clicks and keystrokes to the same Chrome HUNTR is driving"}>
              {control ? "Release control" : "Take control"}
            </button>
          )}
          {stream === "lost" && running && (
            <button type="button" onClick={() => { setStream("connecting"); setReconnect((r) => r + 1); }}
              className="label rounded-md bg-white/5 px-2.5 py-1 text-[10px] text-fg transition-colors hover:bg-white/10">Reconnect</button>
          )}
          {stream === "live" && (
            <button type="button" onClick={toggleFull} aria-label={full ? "Exit fullscreen" : "Maximize live view"}
              title={full ? "Exit fullscreen (Esc)" : "Maximize — fill the screen so you can see and click the page"}
              className="grid h-6 w-6 place-items-center rounded-md bg-white/5 text-fg transition-colors hover:bg-white/10">
              {full ? (
                <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" aria-hidden><path d="M6 2v2.5a1.5 1.5 0 0 1-1.5 1.5H2M10 2v2.5A1.5 1.5 0 0 0 11.5 6H14M6 14v-2.5A1.5 1.5 0 0 0 4.5 10H2M10 14v-2.5a1.5 1.5 0 0 1 1.5-1.5H14" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" /></svg>
              ) : (
                <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" aria-hidden><path d="M2 6V3.5A1.5 1.5 0 0 1 3.5 2H6M14 6V3.5A1.5 1.5 0 0 0 12.5 2H10M2 10v2.5A1.5 1.5 0 0 0 3.5 14H6M14 10v2.5a1.5 1.5 0 0 1-1.5 1.5H10" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" /></svg>
              )}
            </button>
          )}
        </div>
      </figcaption>

      {/* the glass */}
      <div className={`relative w-full bg-black ${full ? "min-h-0 flex-1" : "aspect-[16/10]"}`}>
        {running ? (
          <VncViewer huntId={hunt.hunt_id} bare control={control} onControlChange={setControl} onStatus={setStream} reconnectSignal={reconnect} />
        ) : (
          <div className="grid h-full w-full place-items-center px-6 text-center text-sm text-muted">
            {hunt.status === "done" ? "Operation complete — the live browser has closed." : "The live browser opens the moment the hunt starts running."}
          </div>
        )}

        {/* gunsight overlay — reticle + scanlines, purely decorative, behind captions */}
        {running && stream === "live" && (
          <div aria-hidden className="vp-scope pointer-events-none absolute inset-0 z-[2]">
            <span className="vp-reticle" style={{ borderColor: `color-mix(in srgb, ${edge} 55%, transparent)` }} />
            <span className="vp-tick vp-tick-t" style={{ background: edge }} />
            <span className="vp-tick vp-tick-b" style={{ background: edge }} />
            <span className="vp-tick vp-tick-l" style={{ background: edge }} />
            <span className="vp-tick vp-tick-r" style={{ background: edge }} />
          </div>
        )}

        {/* corner HUD coordinates */}
        {running && stream === "live" && (
          <div aria-hidden className="pointer-events-none absolute right-3 top-2.5 z-[3] font-mono text-[9.5px] uppercase tracking-[0.14em] text-green/70">
            CDP · headful chrome
          </div>
        )}

        {/* the agent's action, projected on the glass (the hero annotation) */}
        {running && stream === "live" && action && !control && (
          <div className="pointer-events-none absolute inset-x-0 bottom-0 z-[3] bg-gradient-to-t from-black/85 via-black/45 to-transparent px-3.5 pb-3 pt-10">
            <div className="flex items-center gap-2">
              <span className="hud shrink-0 rounded-sm bg-green/15 px-1.5 py-0.5 text-[9px] uppercase tracking-[0.16em] text-green">action</span>
              <span key={action} className="vp-action min-w-0 flex-1 truncate font-mono text-[12px] text-fg/90">{action}</span>
            </div>
          </div>
        )}

        {/* control mode: operator is co-driving */}
        {running && stream === "live" && control && (
          <div className="pointer-events-none absolute inset-x-0 bottom-0 z-[3] bg-gradient-to-t from-black/85 to-transparent px-3.5 pb-3 pt-10 text-center">
            <p className="hud text-[10px] uppercase tracking-[0.14em] text-high/90">your input reaches the live browser · Esc to release</p>
          </div>
        )}
      </div>
    </figure>
  );
}

/* ── per-phase elapsed clock (client-side, ticks while running) ─────────── */
function usePhaseElapsed(cur: number, running: boolean): number[] {
  // enteredAt[i] = timestamp the hunt first reached phase i this session
  const enteredAt = useRef<number[]>([]);
  const [, tick] = useState(0);
  const now = Date.now();
  if (enteredAt.current[cur] == null) enteredAt.current[cur] = now;
  // backfill earlier phases we jumped past (unknown start → mark as entered now)
  for (let i = 0; i < cur; i++) if (enteredAt.current[i] == null) enteredAt.current[i] = now;

  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [running]);

  return PHASES.map((_, i) => {
    const start = enteredAt.current[i];
    if (start == null) return null as unknown as number; // not reached
    const end = i < cur ? (enteredAt.current[i + 1] ?? now) : now;
    return Math.max(0, end - start);
  });
}

/* ── root ───────────────────────────────────────────────────────────────── */
export function LiveOperation({ hunt: initial }: { hunt: Hunt }) {
  const [hunt, setHunt] = useState<Hunt>(initial);
  const [art, setArt] = useState<HuntArtifacts | null>(null);
  const running = hunt.status === "running" || hunt.status === "queued";

  // poll hunt status every 5s (data contract), artifacts every 15s
  useEffect(() => { setHunt(initial); }, [initial.hunt_id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    let alive = true;
    const load = () => getHunt(initial.hunt_id).then((h) => { if (alive) setHunt(h); }).catch(() => {});
    load();
    if (!running) return () => { alive = false; };
    const t = setInterval(load, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [initial.hunt_id, running]);
  useEffect(() => {
    let alive = true;
    const load = () => getHuntArtifacts(initial.hunt_id).then((a) => { if (alive) setArt(a); }).catch(() => {});
    load();
    if (!running) return () => { alive = false; };
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, [initial.hunt_id, running]);

  const done = hunt.status === "done";
  const rawCur = phaseIndex(hunt.stage, hunt.status);
  // never walk the chain backwards within a session
  const maxRef = useRef(0);
  if (running && rawCur > maxRef.current) maxRef.current = rawCur;
  const cur = running ? Math.max(rawCur, maxRef.current) : rawCur;
  const pct = Math.max(0, Math.min(100, hunt.pct ?? 0));
  const elapsed = usePhaseElapsed(cur, hunt.status === "running");

  return (
    <section className="enter space-y-4">
      {/* operation header */}
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span className="hud flex items-center gap-2 text-[11px] uppercase tracking-[0.18em] text-fg">
          <span className={running ? "live-dot" : ""} />{done ? "operation complete" : hunt.status === "queued" ? "operation arming" : "operation live"}
        </span>
        <span className="font-mono text-xs text-faint">· {hunt.target}</span>
        {hunt.mode && <span className="chip mute">{hunt.mode}</span>}
        <span className="ml-auto flex items-center gap-2">
          <span className="hud text-[10px] uppercase tracking-[0.14em] text-faint">phase {Math.min(cur, PHASES.length - 1) + 1}/{PHASES.length}</span>
          <span className="numeral text-xl text-fg tabular-nums">{pct}%</span>
        </span>
      </header>

      {/* overall progress hairline */}
      <div className="relative h-0.5 w-full overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Overall hunt progress">
        <span className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${pct}%`, background: done ? "var(--green)" : "var(--grad-brand)", transition: "width .8s var(--ease-out)" }} />
      </div>

      {/* the layout: kill-chain rail · hero viewport · findings feed */}
      <div className="grid gap-4 lg:grid-cols-[minmax(230px,0.72fr)_minmax(0,1.55fr)] xl:grid-cols-[minmax(250px,0.68fr)_minmax(0,1.7fr)_minmax(260px,0.82fr)]">
        {/* left rail: kill-chain + telemetry */}
        <div className="order-2 space-y-4 lg:order-1 xl:order-1">
          <div className="panel p-4">
            <KillChain hunt={hunt} cur={cur} done={done} art={art} elapsed={elapsed} />
          </div>
          <Telemetry hunt={hunt} art={art} running={hunt.status === "running"} />
        </div>

        {/* hero viewport */}
        <div className="order-1 lg:order-2 xl:order-2">
          <Viewport hunt={hunt} art={art} />
        </div>

        {/* findings feed — stacks under the viewport on lg, own column on xl */}
        <div className="order-3 lg:col-span-2 xl:col-span-1 xl:order-3">
          <div className="max-h-[520px] lg:max-h-none xl:h-full">
            <FindingsFeed huntId={hunt.hunt_id} live={hunt.status === "running"} count={hunt.findings || 0} />
          </div>
        </div>
      </div>
    </section>
  );
}
