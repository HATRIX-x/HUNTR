// Server component — pure CSS animation (no JS, no scroll-scrub). Light on the main thread.
const LOCK = { x: 600, y: 540 };
const NODES = [
  { x: 120, label: "SQLi" },
  { x: 300, label: "XSS" },
  { x: 470, label: "IDOR" },
  { x: 600, label: "SSRF" },
  { x: 730, label: "CORS" },
  { x: 900, label: "SSTI" },
  { x: 1080, label: "LFI" },
];
const PATHS = NODES.map(({ x }) => {
  const c2x = LOCK.x + (x - LOCK.x) * 0.22;
  return `M ${x} 56 C ${x} 230, ${c2x} 370, ${LOCK.x} ${LOCK.y}`;
});

export function AttackFunnel() {
  return (
    <div className="relative">
      <style>{`
        @keyframes fnComet { from { stroke-dashoffset: 900; } to { stroke-dashoffset: -60; } }
        @keyframes fnPulse { 0%,100% { opacity:.5; } 50% { opacity:.12; } }
        .fn-comet { stroke-dasharray: 48 900; animation: fnComet 2.6s linear infinite; }
        .fn-halo  { stroke-dasharray: 120 900; animation: fnComet 2.6s linear infinite; }
        .fn-ring  { animation: fnPulse 2.2s ease-in-out infinite; }
        @media (prefers-reduced-motion: reduce) {
          .fn-comet, .fn-halo, .fn-ring { animation: none; }
          .fn-comet { stroke-dasharray: none; }
        }
      `}</style>
      <svg viewBox="0 0 1200 620" className="h-[clamp(300px,40vw,540px)] w-full" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        <defs>
          <radialGradient id="fn-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#4ADE80" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#4ADE80" stopOpacity="0" />
          </radialGradient>
        </defs>

        {NODES.map((n, i) => (
          <text key={"t" + i} x={n.x} y={38} textAnchor="middle" className="fill-muted" style={{ font: "600 12px ui-monospace, monospace", letterSpacing: "0.1em" }}>
            {n.label}
          </text>
        ))}
        {NODES.map((n, i) => (
          <circle key={"n" + i} cx={n.x} cy={56} r={3.5} fill={i % 2 ? "#4ADE80" : "#A78BFA"} />
        ))}

        {PATHS.map((d, i) => (
          <path key={"b" + i} d={d} fill="none" stroke="rgba(167,139,250,0.12)" strokeWidth={1} strokeLinecap="round" />
        ))}
        {PATHS.map((d, i) => (
          <path key={"h" + i} className="fn-halo" d={d} fill="none" stroke={i % 2 ? "#4ADE80" : "#A78BFA"} strokeOpacity={0.16} strokeWidth={9} strokeLinecap="round" style={{ animationDelay: `${i * 0.3}s` }} />
        ))}
        {PATHS.map((d, i) => (
          <path key={"c" + i} className="fn-comet" d={d} fill="none" stroke={i % 2 ? "#6ff0a0" : "#c3b2ff"} strokeWidth={2.4} strokeLinecap="round" style={{ animationDelay: `${i * 0.3}s` }} />
        ))}

        <circle cx={LOCK.x} cy={LOCK.y} r={64} fill="url(#fn-glow)" opacity={0.5} />
        <circle className="fn-ring" cx={LOCK.x} cy={LOCK.y} r={24} fill="none" stroke="#4ADE80" strokeWidth={1.5} />
        <circle cx={LOCK.x} cy={LOCK.y} r={6} fill="#4ADE80" />
        <g stroke="#4ADE80" strokeWidth={1.5} opacity={0.75}>
          <line x1={LOCK.x} y1={LOCK.y - 32} x2={LOCK.x} y2={LOCK.y - 18} />
          <line x1={LOCK.x} y1={LOCK.y + 18} x2={LOCK.x} y2={LOCK.y + 32} />
          <line x1={LOCK.x - 32} y1={LOCK.y} x2={LOCK.x - 18} y2={LOCK.y} />
          <line x1={LOCK.x + 18} y1={LOCK.y} x2={LOCK.x + 32} y2={LOCK.y} />
        </g>
        <text x={LOCK.x} y={LOCK.y + 60} textAnchor="middle" className="fill-green" style={{ font: "600 12px ui-monospace, monospace", letterSpacing: "0.14em" }}>
          VALIDATED
        </text>
      </svg>
    </div>
  );
}
