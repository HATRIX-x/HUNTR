import Link from "next/link";
import type { ReactNode } from "react";

/** Shared contact + metadata for every legal document, so one edit updates them all. */
export const SUPPORT_EMAIL = "support@huntr.run";
export const LEGAL_EFFECTIVE = "November 11, 2026";

/** Page shell for a legal document: title, effective date, intro, then the body sections. */
export function LegalPage({
  kicker,
  title,
  intro,
  children,
}: {
  kicker: string;
  title: ReactNode;
  intro: ReactNode;
  children: ReactNode;
}) {
  return (
    <main>
      <section className="border-b border-line">
        <div className="site-wrap pb-14 pt-16 sm:pb-16 sm:pt-24">
          <div className="flex items-center gap-4">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">{kicker}</span>
          </div>
          <h1 className="display mt-6 max-w-[20ch] text-[clamp(2.4rem,7vw,5rem)]">{title}</h1>
          <p className="mt-6 max-w-[62ch] text-lg leading-relaxed text-fg/80">{intro}</p>
          <p className="mt-6 label text-faint">Effective {LEGAL_EFFECTIVE}</p>
        </div>
      </section>
      <section>
        <div className="site-wrap grid gap-12 py-16 sm:py-20">{children}</div>
      </section>
    </main>
  );
}

/** A numbered section within a legal document. */
export function Clause({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <div className="grid gap-4 border-t border-line pt-10 sm:grid-cols-[4rem_1fr] sm:gap-8">
      <div className="numeral text-3xl text-brand sm:text-4xl">{String(n).padStart(2, "0")}</div>
      <div className="max-w-[68ch]">
        <h2 className="display text-2xl sm:text-3xl">{title}</h2>
        <div className="legal-body mt-5 grid gap-4 leading-relaxed text-fg/80">{children}</div>
      </div>
    </div>
  );
}

/** Styled mail link used across the legal pages and the footer. */
export function MailLink({ className = "" }: { className?: string }) {
  return (
    <Link href={`mailto:${SUPPORT_EMAIL}`} className={`ulink text-brand ${className}`}>
      {SUPPORT_EMAIL}
    </Link>
  );
}
