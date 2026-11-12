/** The HUNTR reticle mark — bold version for the header/footer (crisp at small
 *  sizes; matches the favicon). The full grid logo lives at /logo.svg. */
export function BrandMark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 512 512" fill="none" className={className} aria-hidden="true">
      <g
        stroke="#A78BFA"
        strokeWidth="30"
        transform="translate(256,256) scale(1.26) translate(-256,-256)"
      >
        <g strokeLinecap="butt">
          <path d="M166 132.2 A153 153 0 0 1 346 132.2" />
          <path d="M379.8 166 A153 153 0 0 1 379.8 346" />
          <path d="M346 379.8 A153 153 0 0 1 166 379.8" />
          <path d="M132.2 346 A153 153 0 0 1 132.2 166" />
        </g>
        <g strokeLinecap="round">
          <line x1="256" y1="55" x2="256" y2="188" />
          <line x1="256" y1="324" x2="256" y2="457" />
          <line x1="55" y1="256" x2="188" y2="256" />
          <line x1="324" y1="256" x2="457" y2="256" />
        </g>
      </g>
      <circle cx="256" cy="256" r="52" fill="#79DC89" />
    </svg>
  );
}
