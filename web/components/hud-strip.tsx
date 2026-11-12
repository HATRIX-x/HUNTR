/** Operator-console telemetry strip. Server component — pure markup + CSS pulse. */
export function HudStrip({ rail = "authorized targets only" }: { rail?: string }) {
  return (
    <div className="hud scanline border-b border-line bg-surface2/50">
      <div className="site-wrap flex flex-wrap items-center gap-x-6 gap-y-1 py-2 text-[10.5px] uppercase tracking-[0.14em] text-muted">
        <span className="flex items-center gap-2 text-fg">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full" style={{ background: "var(--validated)" }} />
          operator online
        </span>
        <span>58 classes</span>
        <span>11 agents</span>
        <span>0 auto-submits</span>
        <span className="text-brand">scope-locked</span>
        <span className="ml-auto hidden sm:inline">{rail}</span>
      </div>
    </div>
  );
}
