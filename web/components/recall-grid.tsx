"use client";
import { useEffect, useRef, useState, useMemo } from "react";
import { gsap } from "gsap";

const COLS = 10;
const ROWS = 3;
const TOTAL = COLS * ROWS; // 30 planted bugs
const MISSED = new Set<number>(); // finds all 30
const FOUND = TOTAL - MISSED.size;

export function RecallGrid() {
  const wrap = useRef<HTMLDivElement | null>(null);
  // Start at the real recall (30/30) so the static HTML — what a crawler or a
  // JS-disabled reviewer sees — is correct. The scan is a reveal enhancement only.
  const [found, setFound] = useState(FOUND);

  const cells = useMemo(
    () =>
      Array.from({ length: TOTAL }, (_, i) => ({
        i,
        col: i % COLS,
        row: Math.floor(i / COLS),
        missed: MISSED.has(i),
      })),
    []
  );

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce || typeof IntersectionObserver === "undefined") return; // leave the final 30/30 in place

    // Already on screen at load? Keep the final state — no flash from 30 -> 0 -> 30.
    const rect = el.getBoundingClientRect();
    const alreadyVisible = rect.top < window.innerHeight && rect.bottom > 0;
    if (alreadyVisible) return;

    let ctx: gsap.Context | null = null;
    let done = false;
    const runReveal = () => {
      if (done) return;
      done = true;
      el.querySelectorAll<SVGElement>(".rc-cell").forEach((c, i) => {
        if (!MISSED.has(i)) c.classList.remove("rc-on");
      });
      setFound(0);
      ctx = gsap.context(() => {
        const scan = el.querySelector(".rc-scan");
        const tl = gsap.timeline();
        tl.fromTo(scan, { attr: { x: 10 } }, { attr: { x: 560 }, duration: 3.0, ease: "none" });
        for (let col = 0; col < COLS; col++) {
          const at = (col / COLS) * 3.0 + 0.15;
          tl.call(
            () => {
              cells
                .filter((c) => c.col === col && !c.missed)
                .forEach((c) => {
                  const node = el.querySelector(`[data-rc="${c.i}"]`);
                  if (node) {
                    node.classList.add("rc-on");
                    gsap.fromTo(node, { scale: 0.6 }, { scale: 1, duration: 0.4, ease: "back.out(2)", transformOrigin: "center", transformBox: "fill-box" });
                  }
                  setFound((f) => Math.min(FOUND, f + 1));
                });
            },
            undefined,
            at
          );
        }
      }, el);
    };

    const io = new IntersectionObserver(
      (es) => es.forEach((e) => e.isIntersecting && runReveal()),
      { threshold: 0.05 }
    );
    io.observe(el);
    return () => {
      io.disconnect();
      ctx?.revert();
    };
  }, [cells]);

  const pad = 30;
  const gw = 540;
  const gh = 170;
  const cellW = gw / COLS;
  const cellH = gh / ROWS;

  return (
    <div ref={wrap} className="w-full rounded-xl border border-brand/25 bg-surface p-6 shadow-[0_0_0_1px_rgba(167,139,250,0.1)]">
      <div className="flex items-center justify-between font-mono text-[11px] uppercase tracking-[0.14em] text-muted">
        <span>ground-truth benchmark</span>
        <span>
          found <b className="text-green">{found}</b> / {TOTAL}
        </span>
      </div>
      <svg viewBox={`0 0 ${gw + pad * 2} ${gh + pad * 2}`} className="mt-3 w-full">
        {/* scan line */}
        <rect className="rc-scan" x={10} y={pad - 6} width={2} height={gh + 12} fill="#A78BFA" opacity={0.5} />
        {cells.map((c) => {
          const cx = pad + c.col * cellW + cellW / 2;
          const cy = pad + c.row * cellH + cellH / 2;
          // Render found cells "on" by default so the static grid matches the 30/30 count.
          return (
            <g key={c.i} data-rc={c.i} className={`rc-cell ${c.missed ? "rc-missed" : "rc-on"}`}>
              <circle cx={cx} cy={cy} r={9} className="rc-ring" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth={1} />
              <circle cx={cx} cy={cy} r={4} className="rc-dot" fill="#3A4150" />
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex items-center gap-5 font-mono text-[10px] uppercase tracking-[0.1em] text-faint">
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-green" /> found &amp; validated</span>
        <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-faint" /> planted</span>
      </div>
      <style>{`
        .rc-dot { transition: fill .3s ease; }
        .rc-ring { transition: stroke .3s ease; }
        .rc-cell.rc-on .rc-dot { fill: #4ADE80; }
        .rc-cell.rc-on .rc-ring { stroke: rgba(74,222,128,0.5); }
      `}</style>
    </div>
  );
}
