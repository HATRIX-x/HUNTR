// Server component — pure CSS radar sweep. No JS, no scroll cost.
const C = 300;
const SPIN = 4.5; // seconds per revolution

type Blip = { a: number; r: number; c: "green" | "purple" | "dim" };
const BLIPS: Blip[] = [
  { a: 35, r: 120, c: "green" },
  { a: 72, r: 210, c: "purple" },
  { a: 110, r: 95, c: "green" },
  { a: 150, r: 235, c: "dim" },
  { a: 192, r: 150, c: "purple" },
  { a: 225, r: 200, c: "green" },
  { a: 262, r: 110, c: "green" },
  { a: 300, r: 240, c: "purple" },
  { a: 330, r: 165, c: "green" },
  { a: 18, r: 250, c: "dim" },
];
const color = { green: "#4ADE80", purple: "#A78BFA", dim: "#5A606C" };
const pos = (a: number, r: number) => ({ x: C + r * Math.sin((a * Math.PI) / 180), y: C - r * Math.cos((a * Math.PI) / 180) });
const QUAD = [
  { a: 0, label: "WEB" },
  { a: 90, label: "API" },
  { a: 180, label: "LOGIC" },
  { a: 270, label: "AUTH" },
];

export function Radar() {
  return (
    <div className="relative mx-auto" style={{ maxWidth: 520 }}>
      <style>{`
        @keyframes radarSpin { to { transform: rotate(360deg); } }
        @keyframes radarBlip { 0%,100% { opacity:.22; transform:scale(1); } 6% { opacity:1; transform:scale(1.6); } 24% { opacity:.5; transform:scale(1); } }
        .radar-sweep { transform-origin: ${C}px ${C}px; animation: radarSpin ${SPIN}s linear infinite; }
        .radar-blip  { transform-box: fill-box; transform-origin: center; animation: radarBlip ${SPIN}s ease-out infinite; }
        @media (prefers-reduced-motion: reduce) { .radar-sweep, .radar-blip { animation: none; } .radar-blip { opacity: 1; } }
      `}</style>
      <svg viewBox="0 0 600 600" className="w-full" aria-hidden="true">
        <defs>
          <radialGradient id="rdGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#A78BFA" stopOpacity="0.14" />
            <stop offset="100%" stopColor="#A78BFA" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="rdSweep" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#A78BFA" stopOpacity="0" />
            <stop offset="100%" stopColor="#A78BFA" stopOpacity="0.28" />
          </linearGradient>
        </defs>

        <circle cx={C} cy={C} r={270} fill="url(#rdGlow)" />
        {[80, 150, 220, 275].map((r) => (
          <circle key={r} cx={C} cy={C} r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={1} />
        ))}
        <line x1={C} y1={25} x2={C} y2={575} stroke="rgba(255,255,255,0.05)" />
        <line x1={25} y1={C} x2={575} y2={C} stroke="rgba(255,255,255,0.05)" />

        {/* sweep */}
        <g className="radar-sweep">
          <path d={`M ${C} ${C} L ${C} 30 A 270 270 0 0 1 ${C + 270 * Math.sin((60 * Math.PI) / 180)} ${C - 270 * Math.cos((60 * Math.PI) / 180)} Z`} fill="url(#rdSweep)" />
          <line x1={C} y1={C} x2={C} y2={30} stroke="#A78BFA" strokeWidth={1.5} strokeOpacity={0.7} />
        </g>

        {/* quadrant labels */}
        {QUAD.map((q) => {
          const p = pos(q.a, 254);
          return (
            <text key={q.label} x={p.x} y={p.y + 4} textAnchor="middle" className="fill-faint" style={{ font: "600 12px ui-monospace, monospace", letterSpacing: "0.14em" }}>
              {q.label}
            </text>
          );
        })}

        {/* blips */}
        {BLIPS.map((b, i) => {
          const p = pos(b.a, b.r);
          const delay = (b.a / 360) * SPIN;
          return (
            <g key={i}>
              <circle cx={p.x} cy={p.y} r={b.c === "dim" ? 3 : 4.5} fill={color[b.c]} className="radar-blip" style={{ animationDelay: `${delay}s` }} />
            </g>
          );
        })}

        {/* center */}
        <circle cx={C} cy={C} r={16} fill="none" stroke="#4ADE80" strokeWidth={1} opacity={0.4} />
        <circle cx={C} cy={C} r={5} fill="#4ADE80" />
      </svg>
    </div>
  );
}
