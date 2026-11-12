import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { Waitlist } from "@/components/waitlist";
import { JsonLd } from "@/components/jsonld";
import { InteractiveHunt } from "@/components/interactive-hunt";
import { Radar } from "@/components/radar";
import { HudStrip } from "@/components/hud-strip";

export const metadata: Metadata = {
  title: "How it works — The autonomous bug bounty pipeline",
  description:
    "How HUNTR works: pick an authorized target; the engine maps the attack surface, tests it by class, validates every finding, and drafts a report-ready write-up.",
  alternates: { canonical: "/platform/" },
  openGraph: {
    title: "How HUNTR works — The autonomous bug bounty pipeline",
    description: "Pick a target, HUNTR maps and tests the surface, validates every finding, and drafts the report.",
    url: "https://huntr.run/platform",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
};

const steps = [
  { n: "01", tag: "Pick", body: "Enter a target you're authorized to test and choose the scope — web, API, mobile, source. Black, grey, or white box. The engine decides the methodology." },
  { n: "02", tag: "Hunt", body: "HUNTR maps the attack surface, tests it class by class, and validates every finding — dropping the false positives before they ever reach you." },
  { n: "03", tag: "Send", body: "Each finding arrives report-ready, reproduction and impact drafted. You review, decide, and submit. Nothing goes out without you." },
];

const engine = [
  ["Recon", "Map the surface", "Enumerates hosts, endpoints, parameters, and auth flows — building the real attack surface before a single payload is sent."],
  ["Test", "58 vuln classes", "Drives targeted tests across injection, access-control, auth, SSRF, logic, and client-side — chosen for the surface it found."],
  ["Validate", "Drop the noise", "Every candidate is re-proven before it counts. False positives are discarded so your queue is signal, not a scanner dump."],
  ["Draft", "Report-ready", "Reproduction steps and impact come written with each finding, in the format your program expects. You review and submit."],
];

export default function Platform() {
  return (
    <main>
      <JsonLd data={{ "@context": "https://schema.org", "@type": "HowTo", name: "How HUNTR hunts a target", step: steps.map((s) => ({ "@type": "HowToStep", name: s.tag, text: s.body })) }} />

      <HudStrip rail="pipeline · end to end" />

      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-16 pt-14 sm:pb-20 sm:pt-20">
          <div className="flex items-center gap-4" data-reveal="up">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">The pipeline</span>
          </div>
          <div className="mt-8 grid items-center gap-12 lg:grid-cols-[1fr_minmax(0,0.98fr)] lg:gap-16">
            <div>
              <h1 className="display text-[clamp(2.7rem,7vw,6rem)]" data-hero>
                <span className="block overflow-hidden"><span data-reveal="up" className="block">One hunt.</span></span>
                <span className="block overflow-hidden"><span data-reveal="up" data-delay="90" className="block text-brand">End to end.</span></span>
              </h1>
              <Reveal as="p" delay={200} className="mt-8 max-w-[52ch] text-lg leading-relaxed text-fg/80">
                Every test, verdict, and dropped false-positive flows through one engine toward a single result: a short
                list of validated, report-ready vulnerabilities. Here&apos;s exactly how a hunt runs.
              </Reveal>
            </div>
            <Reveal delay={200} className="w-full">
              <InteractiveHunt />
            </Reveal>
          </div>
        </div>
      </section>

      {/* PIPELINE */}
      <section className="border-b border-line bg-surface">
        <div className="site-wrap py-20 sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">Three steps</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">Three steps. The rest is <span className="text-brand">automated.</span></h2>
          </Reveal>
          <div className="mt-14 divide-y divide-line border-y border-line">
            {steps.map((s, i) => (
              <Reveal key={s.n} delay={i * 80} className="grid items-start gap-6 py-10 md:grid-cols-[auto_1fr] md:gap-12">
                <div className="numeral text-7xl text-brand sm:text-8xl">{s.n}</div>
                <div>
                  <h3 className="display text-3xl sm:text-4xl">{s.tag}</h3>
                  <p className="mt-4 max-w-[60ch] text-lg leading-relaxed text-muted">{s.body}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* THE RADAR */}
      <section className="overflow-hidden border-b border-line">
        <div className="site-wrap py-20 sm:py-28">
          <div className="grid items-center gap-12 lg:grid-cols-[1fr_minmax(0,0.9fr)] lg:gap-16">
            <Reveal type="mask">
              <span className="label text-brand">Live coverage</span>
              <h2 className="display mt-4 max-w-[16ch] text-[clamp(2rem,5vw,4rem)]">
                Nothing off <span className="text-brand">the radar.</span>
              </h2>
              <p className="mt-5 max-w-[48ch] text-lg text-fg/70">
                HUNTR sweeps the whole attack surface — every host, endpoint, and parameter across web, API, auth and
                logic — lighting up what&apos;s real and dropping the noise.
              </p>
            </Reveal>
            <Reveal delay={150} className="w-full">
              <Radar />
            </Reveal>
          </div>
        </div>
      </section>

      {/* UNDER THE HOOD */}
      <section className="border-b border-line">
        <div className="site-wrap py-24 sm:py-32">
          <Reveal type="mask">
            <span className="label text-green">Under the hood</span>
            <h2 className="display mt-6 max-w-[18ch] text-[clamp(2.2rem,6vw,5rem)]">A real methodology — not a single scan.</h2>
          </Reveal>
          <div className="mt-16 grid gap-px overflow-hidden border border-line sm:grid-cols-2" data-reveal-group>
            {engine.map(([k, h, p], i) => (
              <div key={h} className="lantern bg-surface p-8 sm:p-10" data-lantern>
                <div className="label text-faint">0{i + 1} · {k}</div>
                <h3 className="display mt-5 text-2xl sm:text-3xl">{h}</h3>
                <p className="mt-3 max-w-[48ch] leading-relaxed text-muted">{p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="bg-brand text-brand-ink">
        <div className="site-wrap py-24 text-center sm:py-28">
          <Reveal type="mask">
            <span className="label text-brand-ink/70">Early access</span>
            <h2 className="display mx-auto mt-6 max-w-[16ch] text-[clamp(2.4rem,6.5vw,5.5rem)] text-brand-ink">See it run on your targets.</h2>
          </Reveal>
          <Reveal delay={150} className="mx-auto mt-10 flex max-w-md justify-center">
            <Waitlist onAccent className="w-full" />
          </Reveal>
        </div>
      </section>
    </main>
  );
}
