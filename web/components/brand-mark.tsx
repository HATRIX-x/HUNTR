/** The HUNTR reticle mark — three hues, three stages of a hunt:
 *  purple ring (aim) · cyan prongs (probe) · green core (confirmed lock).
 *  Colors come from tokens. `glow` adds the hero halo; `lock` plays the one-shot
 *  lock-on animation (ring swings in, prongs converge, core confirms). */
export function BrandMark({ className = "", glow = false, lock = false }: { className?: string; glow?: boolean; lock?: boolean }) {
  return (
    <svg
      viewBox="0 0 512 512"
      fill="none"
      className={`${lock ? "mark-lock " : ""}${className}`}
      aria-hidden="true"
      style={glow ? { filter: "drop-shadow(0 0 16px var(--brand-a40)) drop-shadow(0 0 22px var(--cyan-a20)) drop-shadow(0 0 28px var(--green-a20))" } : undefined}
    >
      <g strokeWidth="30" transform="translate(256,256) scale(1.26) translate(-256,-256)">
        <g className="mark-ring" strokeLinecap="butt" style={{ stroke: "var(--brand)" }}>
          <path d="M166 132.2 A153 153 0 0 1 346 132.2" />
          <path d="M379.8 166 A153 153 0 0 1 379.8 346" />
          <path d="M346 379.8 A153 153 0 0 1 166 379.8" />
          <path d="M132.2 346 A153 153 0 0 1 132.2 166" />
        </g>
        <g className="mark-prongs" strokeLinecap="round" style={{ stroke: "var(--cyan)" }}>
          <line x1="256" y1="55" x2="256" y2="188" />
          <line x1="256" y1="324" x2="256" y2="457" />
          <line x1="55" y1="256" x2="188" y2="256" />
          <line x1="324" y1="256" x2="457" y2="256" />
        </g>
      </g>
      <circle className="mark-core" cx="256" cy="256" r="52" style={{ fill: "var(--green)" }} />
    </svg>
  );
}
