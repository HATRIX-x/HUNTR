import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { Waitlist } from "@/components/waitlist";

export const metadata: Metadata = {
  title: "Request access — Early access",
  description:
    "Request early access to HUNTR, the autonomous AI operator for bug bounty. Priority onboarding and a direct line to the team.",
  alternates: { canonical: "/access/" },
  openGraph: {
    title: "Request access — HUNTR early access",
    description: "Priority onboarding and a direct line to the team. Request early access to the autonomous operator for bug bounty.",
    url: "https://huntr.run/access",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
};

const gets = [
  ["Priority onboarding", "First in line when access opens, with setup help so you're hunting on day one."],
  ["Direct line", "Talk to the team building it. Your feedback shapes what ships next."],
  ["Human-gated", "HUNTR drafts; you submit. Nothing goes out without you, on authorized targets only."],
];

export default function Access() {
  return (
    <main>
      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-20 pt-16 text-center sm:pb-28 sm:pt-24">
          <div className="flex items-center justify-center gap-4" data-reveal="up">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">Early access</span>
          </div>
          <h1 className="display mx-auto mt-8 max-w-[14ch] text-[clamp(3rem,11vw,9.5rem)]" data-hero>
            <span className="block overflow-hidden"><span data-reveal="up" className="block">Get on the <span className="text-brand">hunt.</span></span></span>
          </h1>
          <Reveal as="p" delay={160} className="mx-auto mt-8 max-w-[52ch] text-lg leading-relaxed text-fg/80">
            HUNTR is onboarding early operators now. Request access and we&apos;ll reach out when your spot opens —
            priority onboarding and a direct line to the team.
          </Reveal>
          <Reveal delay={240} className="mx-auto mt-10 flex max-w-md justify-center">
            <Waitlist className="w-full [&_form]:mx-auto" />
          </Reveal>
          <Reveal delay={320}>
            <p className="mt-6 label text-muted">No spam — launch notice only · authorized targets only</p>
          </Reveal>
        </div>
      </section>

      {/* WHAT YOU GET */}
      <section className="bg-surface">
        <div className="site-wrap py-20 sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">What you get</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">Early operators get <span className="text-brand">more.</span></h2>
          </Reveal>
          <div className="mt-14 grid gap-px overflow-hidden border border-line sm:grid-cols-3" data-reveal-group>
            {gets.map(([h, p], i) => (
              <div key={h} className="lantern bg-surface2 p-8 sm:p-10" data-lantern>
                <div className="numeral text-5xl text-brand">0{i + 1}</div>
                <h3 className="display mt-6 text-2xl">{h}</h3>
                <p className="mt-3 leading-relaxed text-muted">{p}</p>
              </div>
            ))}
          </div>
          <Reveal className="mt-12 flex flex-wrap justify-center gap-4">
            <Link href="/platform" className="btn-outline">How it works</Link>
            <Link href="/benchmark" className="btn-outline">See the benchmark</Link>
          </Reveal>
        </div>
      </section>
    </main>
  );
}
