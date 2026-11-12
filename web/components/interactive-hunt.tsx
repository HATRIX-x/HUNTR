"use client";
import { useCallback, useEffect, useRef, useState } from "react";

type Verdict = "valid" | "drop";
type F = { sev: "CRIT" | "HIGH" | "MED" | "LOW"; cls: string; path: string; verdict: Verdict };
const FINDINGS: F[] = [
  { sev: "CRIT", cls: "SQLi", path: "/items?id=", verdict: "valid" },
  { sev: "HIGH", cls: "IDOR", path: "/account/{id}", verdict: "valid" },
  { sev: "MED", cls: "CORS", path: "/api/data", verdict: "drop" },
  { sev: "HIGH", cls: "SSRF", path: "/fetch?url=", verdict: "valid" },
  { sev: "LOW", cls: "XSS", path: "/search?q=", verdict: "drop" },
];
const PRESETS = ["acme.api", "shop.example", "api.vault.io"];
const sevClass: Record<F["sev"], string> = { CRIT: "crit", HIGH: "high", MED: "test", LOW: "test" };

export function InteractiveHunt() {
  const [target, setTarget] = useState("acme.api");
  const [phase, setPhase] = useState<"idle" | "recon" | "test" | "report">("idle");
  const [endpoints, setEndpoints] = useState(94);
  const [shown, setShown] = useState(FINDINGS.length);
  const [resolved, setResolved] = useState(FINDINGS.length);
  const [cov, setCov] = useState(100);
  const [running, setRunning] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  const runId = useRef(0);

  const clear = () => { timers.current.forEach(clearTimeout); timers.current = []; };
  const sleep = (ms: number) => new Promise<void>((r) => timers.current.push(setTimeout(r, ms)));

  const run = useCallback(async () => {
    clear();
    const id = ++runId.current;
    const alive = () => id === runId.current;
    setRunning(true);
    setPhase("recon"); setEndpoints(0); setShown(0); setResolved(0); setCov(0);
    for (let e = 0; e <= 94; e += 7) { if (!alive()) return; setEndpoints(Math.min(e, 94)); await sleep(32); }
    setEndpoints(94); await sleep(360);
    if (!alive()) return;
    setPhase("test");
    for (let i = 0; i < FINDINGS.length; i++) {
      if (!alive()) return;
      setShown(i + 1); await sleep(440);
      if (!alive()) return;
      setResolved(i + 1); setCov(Math.round(((i + 1) / FINDINGS.length) * 100)); await sleep(520);
    }
    setCov(100); await sleep(400);
    if (!alive()) return;
    setPhase("report"); setRunning(false);
  }, []);

  useEffect(() => () => clear(), []);

  const slice = FINDINGS.slice(0, resolved);
  const validated = slice.filter((f) => f.verdict === "valid").length;
  const noise = slice.filter((f) => f.verdict === "drop").length;
  const phaseLabel = phase === "idle" ? "ready — enter a target"
    : phase === "recon" ? `mapping surface · ${endpoints} endpoints`
    : phase === "test" ? "testing · validating" : "report drafted · ready to review";

  return (
    <div className="w-full overflow-hidden rounded-xl border border-brand/25 bg-surface shadow-[0_0_0_1px_rgba(167,139,250,0.12),0_40px_120px_-50px_rgba(167,139,250,0.4)]">
      {/* top bar */}
      <div className="flex items-center gap-2 border-b border-line bg-surface2 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
        <span className="hud ml-2 text-[11px] uppercase tracking-[0.12em] text-muted">huntr · fire control</span>
        <span className={`hud ml-auto flex items-center gap-2 text-[10.5px] uppercase tracking-[0.1em] ${running ? "text-[color:var(--testing)]" : phase === "report" ? "text-[color:var(--validated)]" : "text-muted"}`}>
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: running ? "var(--testing)" : phase === "report" ? "var(--validated)" : "var(--faint,#5A606C)" }} />
          {running ? "running" : phase === "report" ? "done" : "idle"}
        </span>
      </div>

      {/* command line — editable */}
      <div className="hud flex items-center gap-2 border-b border-line px-4 py-3 text-[13px]">
        <span className="text-brand">$</span><span className="text-muted">hunt</span>
        <span className="text-muted">https://</span>
        <input
          data-hot
          value={target}
          onChange={(e) => setTarget(e.target.value.replace(/\s/g, ""))}
          onKeyDown={(e) => { if (e.key === "Enter" && !running) run(); }}
          spellCheck={false}
          className="min-w-0 flex-1 bg-transparent text-fg outline-none placeholder:text-faint"
          placeholder="target.api"
          aria-label="Target to hunt"
        />
        <button
          onClick={() => !running && run()}
          disabled={running}
          className="hud shrink-0 rounded-md bg-brand px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.1em] text-brand-ink transition hover:brightness-110 disabled:opacity-50"
        >
          {running ? "hunting…" : phase === "report" ? "re-run" : "run hunt ↵"}
        </button>
      </div>

      {/* preset targets */}
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5">
        <span className="hud text-[10px] uppercase tracking-[0.12em] text-faint">try</span>
        {PRESETS.map((p) => (
          <button key={p} onClick={() => { setTarget(p); }} className="hud rounded border border-line px-2 py-0.5 text-[11px] text-muted transition hover:border-brand/50 hover:text-fg">{p}</button>
        ))}
      </div>

      {/* phase + counters */}
      <div className="hud flex items-center justify-between border-b border-line px-4 py-2.5 text-[11px] uppercase tracking-[0.1em]">
        <span className="text-faint">{phaseLabel}</span>
        <span className="flex gap-4 text-faint">
          <span>tested <b className="text-fg">{resolved}</b></span>
          <span>valid <b style={{ color: "var(--validated)" }}>{validated}</b></span>
          <span>noise <b className="text-muted">{noise}</b></span>
        </span>
      </div>

      {/* findings */}
      <div className="hud min-h-[244px] px-4 py-3 text-[12.5px]">
        {FINDINGS.map((f, i) => {
          const isShown = i < shown, isResolved = i < resolved;
          return (
            <div key={f.cls + f.path} className={`flex items-center gap-3 py-[7px] transition-all duration-500 ${isShown ? "translate-x-0 opacity-100" : "-translate-x-2 opacity-0"} ${isResolved && f.verdict === "drop" ? "opacity-40" : ""}`}>
              <span className={`chip ${sevClass[f.sev]} shrink-0`}>{f.sev}</span>
              <span className="w-12 shrink-0 text-fg">{f.cls}</span>
              <span className="truncate text-muted">{f.path}</span>
              <span className="ml-auto shrink-0">
                {!isResolved ? <span style={{ color: "var(--testing)" }}>testing…</span>
                  : f.verdict === "valid" ? <span style={{ color: "var(--validated)" }}>✓ validated</span>
                  : <span className="text-muted line-through">dropped</span>}
              </span>
            </div>
          );
        })}
      </div>

      {/* coverage + report */}
      <div className="border-t border-line px-4 py-3">
        <div className="hud flex items-center justify-between text-[10px] uppercase tracking-[0.12em] text-faint">
          <span>coverage</span><span className="text-brand">{cov}%</span>
        </div>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-surface2">
          <div className="h-full rounded-full transition-all duration-500" style={{ width: `${cov}%`, background: "linear-gradient(90deg, var(--brand), var(--validated))" }} />
        </div>
        <div className={`hud mt-3 flex items-center gap-2 text-[11px] transition-opacity duration-500 ${phase === "report" ? "opacity-100" : "opacity-0"}`}>
          <span style={{ color: "var(--validated)" }}>▸</span>
          <span className="text-muted">report drafted — reproduction + impact · </span>
          <span className="text-fg">you review &amp; submit</span>
        </div>
      </div>
    </div>
  );
}
