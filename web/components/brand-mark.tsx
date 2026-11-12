/** The HUNTR reticle mark — a broken brand-purple ring with crosshair prongs
 *  around a green target dot. Kept in sync with app/icon.svg (the favicon). */
export function BrandMark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" fill="none" className={className} aria-hidden="true">
      <g stroke="#A78BFA" strokeWidth="8.5" strokeLinecap="round">
        <circle cx="50" cy="50" r="30" strokeDasharray="35 12" strokeDashoffset="17.5" />
        <line x1="50" y1="21" x2="50" y2="37" />
        <line x1="50" y1="79" x2="50" y2="63" />
        <line x1="21" y1="50" x2="37" y2="50" />
        <line x1="79" y1="50" x2="63" y2="50" />
      </g>
      <circle cx="50" cy="50" r="9" fill="#4ADE80" />
    </svg>
  );
}
