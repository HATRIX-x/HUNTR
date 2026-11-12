"use client";
import { useEffect, useRef, useMemo } from "react";
import { gsap } from "gsap";

const W = 1040;
const H = 420;
const CY = H / 2;

const COLS = [
  { x: 90, label: "TARGET", n: 1, tone: "brand" },
  { x: 300, label: "RECON", n: 4, tone: "brand" },
  { x: 520, label: "TEST", n: 5, tone: "brand" },
  { x: 740, label: "VALIDATE", n: 3, tone: "mix" },
  { x: 950, label: "REPORT", n: 1, tone: "green" },
];

type Node = { x: number; y: number; col: number; valid: boolean };

export function NeuralBrain() {
  const wrap = useRef<HTMLDivElement | null>(null);

  const { nodes, synapses } = useMemo(() => {
    const nodes: Node[] = [];
    COLS.forEach((c, ci) => {
      const gap = 62;
      const start = CY - ((c.n - 1) * gap) / 2;
      for (let i = 0; i < c.n; i++) {
        nodes.push({ x: c.x, y: start + i * gap, col: ci, valid: ci < 3 ? true : i < 2 });
      }
    });
    const synapses: { x1: number; y1: number; x2: number; y2: number; seg: number }[] = [];
    for (let ci = 0; ci < COLS.length - 1; ci++) {
      const a = nodes.filter((n) => n.col === ci);
      const b = nodes.filter((n) => n.col === ci + 1);
      a.forEach((na) => b.forEach((nb) => synapses.push({ x1: na.x, y1: na.y, x2: nb.x, y2: nb.y, seg: ci })));
    }
    return { nodes, synapses };
  }, []);

  useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const el = wrap.current;
    if (!el || reduce) return;

    const ctx = gsap.context(() => {
      gsap.set(".nb-node", { transformOrigin: "center", transformBox: "fill-box" });
      const tl = gsap.timeline({ repeat: -1, repeatDelay: 0.5, defaults: { ease: "power2.out" } });

      for (let seg = 0; seg < COLS.length - 1; seg++) {
        tl.to(
          `.nb-node-c${seg}`,
          { scale: 1.5, duration: 0.3 },
          seg === 0 ? 0 : ">-0.25"
        )
          .to(`.nb-node-c${seg}`, { scale: 1, duration: 0.5 }, ">")
          .fromTo(`.nb-syn-${seg}`, { opacity: 0.08 }, { opacity: 0.85, duration: 0.35, stagger: 0.004 }, "<0.05")
          .to(`.nb-syn-${seg}`, { opacity: 0.08, duration: 0.5 }, ">0.15")
          .to(`.nb-label-${seg}`, { opacity: 1, duration: 0.2 }, "<-0.5")
          .to(`.nb-label-${seg}`, { opacity: 0.4, duration: 0.4 }, ">0.3");
      }
      // final REPORT fire
      tl.to(`.nb-node-c${COLS.length - 1}`, { scale: 1.6, duration: 0.3 }, ">-0.2")
        .to(`.nb-node-c${COLS.length - 1}`, { scale: 1, duration: 0.5 }, ">")
        .to(`.nb-label-${COLS.length - 1}`, { opacity: 1, duration: 0.2 }, "<-0.5")
        .to(`.nb-label-${COLS.length - 1}`, { opacity: 0.4, duration: 0.5 }, ">0.4");

      // idle shimmer on nodes
      gsap.to(".nb-node", { opacity: 0.6, repeat: -1, yoyo: true, duration: 1.6, stagger: { each: 0.08, from: "random" }, ease: "sine.inOut" });
    }, el);

    return () => ctx.revert();
  }, []);

  const colorOf = (n: Node) =>
    COLS[n.col].tone === "green" ? "#4ADE80" : COLS[n.col].tone === "mix" ? (n.valid ? "#4ADE80" : "#5A606C") : "#A78BFA";

  return (
    <div ref={wrap} className="relative">
      <svg viewBox={`0 0 ${W} ${H + 46}`} className="h-[clamp(260px,32vw,420px)] w-full" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        {/* synapses */}
        {synapses.map((s, i) => (
          <line key={i} className={`nb-syn-${s.seg}`} x1={s.x1} y1={s.y1} x2={s.x2} y2={s.y2} stroke="#A78BFA" strokeWidth={1} opacity={0.08} />
        ))}
        {/* nodes */}
        {nodes.map((n, i) => (
          <circle
            key={i}
            className={`nb-node nb-node-c${n.col}`}
            cx={n.x}
            cy={n.y}
            r={n.col === 0 || n.col === COLS.length - 1 ? 8 : 5.5}
            fill={colorOf(n)}
          />
        ))}
        {/* stage labels */}
        {COLS.map((c, i) => (
          <text
            key={i}
            className={`nb-label-${i}`}
            x={c.x}
            y={H + 26}
            textAnchor="middle"
            fill={c.tone === "green" ? "#4ADE80" : "#A78BFA"}
            opacity={0.4}
            style={{ font: "700 13px ui-monospace, monospace", letterSpacing: "0.14em" }}
          >
            {c.label}
          </text>
        ))}
        {/* connecting flow line under labels */}
        <line x1={COLS[0].x} y1={H + 40} x2={COLS[COLS.length - 1].x} y2={H + 40} stroke="rgba(255,255,255,0.08)" strokeWidth={1} />
      </svg>
    </div>
  );
}
