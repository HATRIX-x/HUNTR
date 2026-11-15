import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/reveal";

// The early-access waitlist is retired — HUNTR is self-serve now.
// This page stays so old links/bookmarks land somewhere useful instead
// of 404ing; it's noindex and just points at the real funnel.
export const metadata: Metadata = {
  title: "HUNTR is open",
  description: "HUNTR is self-serve — no waitlist. Create an account and start hunting.",
  alternates: { canonical: "/pricing/" },
  robots: { index: false, follow: true },
};

export default function Access() {
  return (
    <main className="site-wrap flex min-h-[calc(100vh-4rem)] flex-col items-center justify-center py-24 text-center">
      <div className="flex items-center gap-4" data-reveal="up">
        <span className="inline-flex items-center gap-2.5 rounded-full border border-line-2 bg-bg/50 py-1.5 pl-2.5 pr-3.5">
          <span className="live-dot" />
          <span className="label text-[10.5px] text-fg/80">No waitlist</span>
        </span>
      </div>
      <h1 className="display mt-8 max-w-[16ch] text-[clamp(2.6rem,8vw,6rem)]" data-hero>
        HUNTR is <span className="text-green">open.</span>
      </h1>
      <Reveal as="p" delay={160} className="mx-auto mt-8 max-w-[50ch] text-lg leading-relaxed text-fg/80">
        The early-access list is gone — you don&apos;t have to wait for us anymore. Create your account,
        load credits, and point HUNTR at a target you&apos;re authorized to test. We run the hunt for you.
      </Reveal>
      <Reveal delay={240} className="mt-10 flex flex-wrap justify-center gap-4">
        <Link href="/signup/" className="btn-grad" data-magnetic>Start hunting</Link>
        <Link href="/pricing/" className="btn-outline">See pricing</Link>
      </Reveal>
      <Reveal delay={320}>
        <p className="mt-6 label text-muted">
          Already have an account? <Link href="/login/" className="ulink text-fg hover:text-brand">Sign in</Link>
        </p>
      </Reveal>
    </main>
  );
}
