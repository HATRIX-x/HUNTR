/** Operator-console telemetry strip. Server component — pure markup + CSS pulse.
 *  Cyan = telemetry numbers; green = the live dot; purple = the scope lock (intent). */
export function HudStrip({ rail = "authorized targets only" }: { rail?: string }) {
  const stats: [string, string][] = [["58", "classes"], ["11", "agents"], ["0", "auto-submits"]];
  return (
    <div className="hud scanline relative border-b border-line bg-surface2/40">
      <div className="site-wrap flex flex-wrap items-center gap-x-6 gap-y-1 py-2 text-[10.5px] uppercase tracking-[0.14em] text-muted">
        <span className="flex items-center gap-2 text-fg">
          <span className="live-dot" />
          operator online
        </span>
        {stats.map(([n, k]) => (
          <span key={k}>
            <span className="text-cyan tabular">{n}</span> {k}
          </span>
        ))}
        <span className="flex items-center gap-1.5 text-brand">
          <svg viewBox="0 0 12 12" className="h-2.5 w-2.5" aria-hidden><rect x="2" y="5.5" width="8" height="5.5" rx="1" fill="currentColor" /><path d="M4 5.5V4a2 2 0 0 1 4 0v1.5" stroke="currentColor" strokeWidth="1.3" fill="none" /></svg>
          scope-locked
        </span>
        <span className="ml-auto hidden sm:inline">{rail}</span>
      </div>
      <div className="grad-rule absolute inset-x-0 bottom-0 opacity-50" aria-hidden />
    </div>
  );
}
