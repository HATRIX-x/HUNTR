"use client";
import { useEffect, useRef, useState } from "react";

type Verdict = "valid" | "drop";
const TARGET = "https://acme.api";
const FINDINGS: { sev: string; cls: string; path: string; verdict: Verdict }[] = [
  { sev: "CRIT", cls: "SQLi", path: "/items?id=", verdict: "valid" },
  { sev: "HIGH", cls: "IDOR", path: "/account/{id}", verdict: "valid" },
  { sev: "MED", cls: "CORS", path: "/api/data", verdict: "drop" },
  { sev: "HIGH", cls: "SSRF", path: "/fetch?url=", verdict: "valid" },
  { sev: "LOW", cls: "XSS", path: "/search?q=", verdict: "drop" },
];

const sevColor: Record<string, string> = {
  CRIT: "text-[#ff6b6b] border-[#ff6b6b]/40",
  HIGH: "text-[#E7C983] border-[#E7C983]/40",
  MED: "text-brand border-brand/40",
  LOW: "text-muted border-line",
};

export function FireControl() {
  // Initialise to the completed "report" snapshot so the static HTML (and any
  // no-JS / crawler fetch) shows a confident finished hunt — never a bare "0".
  // The live typing demo still plays as an enhancement (see the first-hold below).
  const [typed, setTyped] = useState(TARGET);
  const [phase, setPhase] = useState<"idle" | "recon" | "test" | "report">("report");
  const [endpoints, setEndpoints] = useState(94);
  const [shown, setShown] = useState(FINDINGS.length);
  const [resolved, setResolved] = useState(FINDINGS.length);
  const [cov, setCov] = useState(100);
  const rootRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let mounted = true;
    const timers: ReturnType<typeof setTimeout>[] = [];
    const sleep = (ms: number) => new Promise<void>((r) => timers.push(setTimeout(r, ms)));
    const vis = { current: true };
    let io: IntersectionObserver | null = null;
    if (rootRef.current && typeof IntersectionObserver !== "undefined") {
      io = new IntersectionObserver((es) => es.forEach((e) => (vis.current = e.isIntersecting)), { threshold: 0.05 });
      io.observe(rootRef.current);
    }
    const waitVisible = async () => {
      while (mounted && !vis.current) await sleep(160);
    };

    if (reduce) {
      setTyped(TARGET);
      setPhase("report");
      setEndpoints(94);
      setShown(FINDINGS.length);
      setResolved(FINDINGS.length);
      setCov(100);
      return;
    }

    const reset = () => {
      setTyped("");
      setPhase("idle");
      setEndpoints(0);
      setShown(0);
      setResolved(0);
      setCov(0);
    };

    (async function loop() {
      // Hold the initial completed snapshot on first view (no flash from the
      // static "report" state to 0), then replay the live hunt on every loop.
      let first = true;
      while (mounted) {
        await waitVisible();
        if (first) {
          first = false;
          await sleep(2600);
          continue;
        }
        reset();
        await sleep(500);
        for (let i = 0; i <= TARGET.length; i++) {
          if (!mounted) return;
          setTyped(TARGET.slice(0, i));
          await sleep(55);
        }
        await sleep(380);
        if (!mounted) return;
        setPhase("recon");
        for (let e = 0; e <= 94; e += 6) {
          if (!mounted) return;
          setEndpoints(Math.min(e, 94));
          await sleep(42);
        }
        setEndpoints(94);
        await sleep(420);
        if (!mounted) return;
        setPhase("test");
        for (let i = 0; i < FINDINGS.length; i++) {
          if (!mounted) return;
          setShown(i + 1);
          await sleep(520);
          if (!mounted) return;
          setResolved(i + 1);
          setCov(Math.round(((i + 1) / FINDINGS.length) * 100));
          await sleep(600);
        }
        setCov(100);
        await sleep(500);
        if (!mounted) return;
        setPhase("report");
        await sleep(2600);
      }
    })();

    return () => {
      mounted = false;
      timers.forEach(clearTimeout);
      io?.disconnect();
    };
  }, []);

  const slice = FINDINGS.slice(0, resolved);
  const validated = slice.filter((f) => f.verdict === "valid").length;
  const noise = slice.filter((f) => f.verdict === "drop").length;

  const phaseLabel =
    phase === "idle"
      ? "awaiting target"
      : phase === "recon"
      ? `mapping surface · ${endpoints} endpoints`
      : phase === "test"
      ? "testing · validating"
      : "report drafted · ready to review";

  return (
    <div ref={rootRef} className="w-full overflow-hidden rounded-xl border border-brand/25 bg-surface shadow-[0_0_0_1px_rgba(167,139,250,0.12),0_40px_120px_-50px_rgba(167,139,250,0.35)]">
      {/* top bar */}
      <div className="flex items-center gap-2 border-b border-line bg-surface2 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-2" />
        <span className="ml-2 font-mono text-[11px] uppercase tracking-[0.12em] text-muted">huntr · fire control</span>
        <span className="ml-auto flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.1em] text-green">
          <span className="h-1.5 w-1.5 rounded-full bg-green shadow-[0_0_8px_var(--green,#4ADE80)]" />
          {phase === "report" ? "done" : "running"}
        </span>
      </div>

      {/* command line */}
      <div className="border-b border-line px-4 py-3 font-mono text-[13px]">
        <span className="text-brand">$</span> <span className="text-muted">hunt</span>{" "}
        <span className="text-fg">{typed}</span>
        <span className="ml-0.5 inline-block h-[1.1em] w-[2px] translate-y-[2px] animate-pulse bg-brand" />
      </div>

      {/* phase */}
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5 font-mono text-[11px] uppercase tracking-[0.1em]">
        <span className="text-faint">{phaseLabel}</span>
        <span className="flex gap-4 text-faint">
          <span>
            tested <b className="text-fg">{resolved}</b>
          </span>
          <span>
            valid <b className="text-green">{validated}</b>
          </span>
          <span>
            noise <b className="text-muted">{noise}</b>
          </span>
        </span>
      </div>

      {/* findings */}
      <div className="min-h-[244px] px-4 py-3 font-mono text-[12.5px]">
        {FINDINGS.map((f, i) => {
          const isShown = i < shown;
          const isResolved = i < resolved;
          return (
            <div
              key={f.cls + f.path}
              className={`flex items-center gap-3 py-[7px] transition-all duration-500 ${
                isShown ? "translate-x-0 opacity-100" : "-translate-x-2 opacity-0"
              } ${isResolved && f.verdict === "drop" ? "opacity-40" : ""}`}
            >
              <span className={`shrink-0 border px-1.5 py-0.5 text-[9.5px] font-semibold tracking-wide ${sevColor[f.sev]}`}>
                {f.sev}
              </span>
              <span className="w-12 shrink-0 text-fg">{f.cls}</span>
              <span className="truncate text-muted">{f.path}</span>
              <span className="ml-auto shrink-0">
                {!isResolved ? (
                  <span className="text-faint">testing…</span>
                ) : f.verdict === "valid" ? (
                  <span className="text-green">✓ validated</span>
                ) : (
                  <span className="text-muted line-through">dropped</span>
                )}
              </span>
            </div>
          );
        })}
      </div>

      {/* coverage + report */}
      <div className="border-t border-line px-4 py-3">
        <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.12em] text-faint">
          <span>coverage</span>
          <span className="text-brand">{cov}%</span>
        </div>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-surface2">
          <div
            className="h-full rounded-full bg-gradient-to-r from-brand to-green transition-all duration-500"
            style={{ width: `${cov}%` }}
          />
        </div>
        <div
          className={`mt-3 flex items-center gap-2 font-mono text-[11px] transition-opacity duration-500 ${
            phase === "report" ? "opacity-100" : "opacity-0"
          }`}
        >
          <span className="text-green">▸</span>
          <span className="text-muted">report drafted — reproduction + impact · </span>
          <span className="text-fg">you review &amp; submit</span>
        </div>
      </div>
    </div>
  );
}
