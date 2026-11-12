/* eslint-disable @next/next/no-img-element */
/** The HUNTR reticle logo — the exact asset (public/logo.svg), used in the
 *  header and footer. The favicon uses the same file via app/icon.svg. */
export function BrandMark({ className = "" }: { className?: string }) {
  return <img src="/logo.svg" alt="HUNTR" className={className} />;
}
