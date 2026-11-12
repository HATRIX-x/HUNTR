/** The HUNTR reticle mark — four brand arcs around a green target dot. */
export function BrandMark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 100 100" fill="none" className={className} aria-hidden="true">
      <circle
        cx="50" cy="50" r="30" fill="none" stroke="#A78BFA" strokeWidth="8"
        strokeLinecap="round" strokeDasharray="30 17.1" strokeDashoffset="15"
      />
      <circle cx="50" cy="50" r="9" fill="#4ADE80" />
    </svg>
  );
}
