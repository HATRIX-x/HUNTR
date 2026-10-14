import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { JsonLd } from "@/components/jsonld";
import { ARTICLES } from "@/components/research-data";

export const metadata: Metadata = {
  title: "Research — Field notes on autonomous security testing",
  description:
    "No-hype writing on automated penetration testing, vulnerability scanning, and AI security tooling — from the team building the autonomous bug bounty operator.",
  alternates: { canonical: "/research/" },
  openGraph: {
    title: "HUNTR Research — Field notes on autonomous security testing",
    description: "No-hype writing on automated pentesting, vulnerability scanning, and AI security tooling.",
    url: "https://huntr.run/research",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
};

export default function Research() {
  return (
    <main>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "Blog",
          name: "HUNTR Research",
          url: "https://huntr.run/research/",
          description:
            "Field notes on automated penetration testing, vulnerability scanning, and AI security tooling.",
          blogPost: ARTICLES.map((a) => ({
            "@type": "BlogPosting",
            headline: a.title,
            url: `https://huntr.run/research/${a.slug}/`,
            datePublished: a.published,
            dateModified: a.modified,
            author: { "@type": "Organization", name: "HUNTR" },
          })),
        }}
      />

      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-16 pt-14 sm:pb-20 sm:pt-20">
          <div className="flex items-center gap-4" data-reveal="up">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">Research · Field notes</span>
          </div>
          <h1 className="display mt-8 max-w-[16ch] text-[clamp(2.7rem,7vw,6rem)] leading-[1.01]" data-hero>
            <span className="block overflow-hidden">
              <span data-reveal="up" className="block">We write it</span>
            </span>
            <span className="block overflow-hidden">
              <span data-reveal="up" data-delay="90" className="block">
                <span className="text-outline">like we</span> <span className="text-brand">test it.</span>
              </span>
            </span>
          </h1>
          <Reveal as="p" delay={200} className="mt-8 max-w-[52ch] text-lg leading-relaxed text-fg/80">
            No growth-hacked listicles. Just straight writing on how automated security testing
            actually works — where it earns its keep, and where it just makes noise.
          </Reveal>
        </div>
      </section>

      {/* INDEX */}
      <section className="border-b border-line bg-surface">
        <div className="site-wrap py-16 sm:py-20">
          <div className="grid gap-px overflow-hidden border border-line" data-reveal-group>
            {ARTICLES.map((a, i) => (
              <Link
                key={a.slug}
                href={`/research/${a.slug}`}
                className="lantern group block bg-surface p-7 transition-colors hover:bg-surface2 sm:p-9"
                data-lantern
              >
                <div className="flex items-center gap-3">
                  <span className="numeral text-xl text-brand">0{i + 1}</span>
                  <span className="label text-faint">{a.kicker}</span>
                  <span className="label ml-auto text-faint">{a.readMins} min</span>
                </div>
                <h2 className="display mt-4 max-w-[32ch] text-[clamp(1.4rem,3vw,2.1rem)] leading-tight text-fg">
                  {a.title}
                </h2>
                <p className="mt-3 max-w-[70ch] text-sm leading-relaxed text-muted">{a.dek}</p>
                <span className="label mt-6 inline-flex items-center gap-2 text-brand">
                  Read
                  <span className="transition-transform group-hover:translate-x-1">→</span>
                </span>
              </Link>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
