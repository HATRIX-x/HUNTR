"use client";
import { useEffect, useRef, useState, useMemo } from "react";
import { gsap } from "gsap";

const COLS = 10;
const ROWS = 3;
const TOTAL = COLS * ROWS; // 30 planted bugs
const MISSED = new Set<number>(); // finds all 30

export function RecallGrid() {
  const wrap = useRef<HTMLDivElement | null>(null);
  const [found, setFound] = useState(0);

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
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const el = wrap.current;
    if (!el) return;

    if (reduce) {
      el.querySelectorAll<SVGElement>(".rc-cell").forEach((c, i) => {
        if (!MISSED.has(i)) c.classList.add("rc-on");
      });
      setFound(TOTAL - MISSED.size);
      return;
    }

    const vis = { current: true };
    let io: IntersectionObserver | null = null;
    if (typeof IntersectionObserver !== "undefined") {
      io = new IntersectionObserver((es) => es.forEach((e) => (vis.current = e.isIntersecting)), { threshold: 0.05 });
      io.observe(el);
    }

    const ctx = gsap.context(() => {
      const scan = el.querySelector(".rc-scan");
      const loop = () => {
        if (!vis.current) {
          gsap.delayedCall(0.3, loop);
          return;
        }
        el.querySelectorAll<SVGElement>(".rc-cell").forEach((c) => c.classList.remove("rc-on"));
        setFound(0);
        const tl = gsap.timeline({
          onComplete: () => {
            gsap.delayedCall(1.4, loop);
          },
        });
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
                  setFound((f) => f + 1);
                });
            },
            undefined,
            at
          );
        }
        tl.to({}, { duration: 0.6 });
      };
      loop();
    }, el);

    return () => {
      ctx.revert();
      io?.disconnect();
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
          return (
            <g key={c.i} data-rc={c.i} className={`rc-cell ${c.missed ? "rc-missed" : ""}`}>
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
