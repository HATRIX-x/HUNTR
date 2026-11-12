import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Page not found",
  robots: { index: false, follow: true },
};

export default function NotFound() {
  return (
    <main>
      <section className="border-b border-line">
        <div className="site-wrap flex min-h-[64vh] flex-col items-center justify-center py-24 text-center">
          <div className="flex items-center gap-4">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">Error 404</span>
          </div>
          <h1 className="display mt-8 text-[clamp(4rem,18vw,12rem)] leading-none">
            4<span className="text-brand">0</span>4
          </h1>
          <p className="mt-6 max-w-[46ch] text-lg leading-relaxed text-fg/80">
            This page got away. The link may be broken or the page may have moved — but the hunt
            goes on.
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
            <Link href="/" className="btn-brand">Back to home</Link>
            <Link href="/platform/" className="btn-outline">See how it works</Link>
          </div>
          <nav className="mt-12 flex flex-wrap items-center justify-center gap-x-6 gap-y-2">
            {[
              ["/benchmark/", "Benchmark"],
              ["/pricing/", "Pricing"],
              ["/research/", "Research"],
              ["/access/", "Request access"],
            ].map(([href, label]) => (
              <Link key={href} href={href} className="label ulink text-muted hover:text-fg">
                {label}
              </Link>
            ))}
          </nav>
        </div>
      </section>
    </main>
  );
}
