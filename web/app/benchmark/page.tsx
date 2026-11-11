import type { Metadata } from "next";
import { Reveal } from "@/components/reveal";
import { Stat } from "@/components/stat";
import { Waitlist } from "@/components/waitlist";
import { AttackCoverage } from "@/components/attack-coverage";

export const metadata: Metadata = {
  title: "Benchmark — Measured against ground truth",
  description:
    "HUNTR is measured, not claimed: a benchmark of known-vulnerable targets with certain ground truth across 25 ground-truth classes and 5 suites. Zero auto-submissions.",
  alternates: { canonical: "/benchmark/" },
  openGraph: {
    title: "HUNTR Benchmark — Measured against ground truth",
    description: "Known-vulnerable targets with certain answers. 58 vulnerability classes hunted end-to-end across 5 suites. Zero auto-submissions.",
    url: "https://huntr.run/benchmark",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
};

const suites = [
  ["Local lab", "Known-vuln lab", "Black-box web + API lab. SQLi, XSS, SSTI, SSRF, IDOR, authz, CORS, LFI — answers known cold."],
  ["Auth lab", "Access control", "BFLA, broken access control, privilege boundaries. Tested grey-box."],
  ["ASP.NET", "Framework depth", "Proves the engine retools its methodology for the stack it finds."],
  ["Public", "Real test sites", "Industry-standard vulnweb targets, scored against known baselines."],
  ["Scoring", "Signal vs. noise", "Did it find the bug? Did it cry wolf? Money-weighted, FP-penalized."],
  ["Control", "Deterministic", "A no-LLM path makes core coverage reproducible — run to run."],
];

const classes = ["sqli","xss","ssti","ssrf","idor","authz","bfla","cors","lfi","nosqli","crlf","xpath","ldap","cmdi","oauth","graphql","deserialization","mass-assignment","prototype-pollution","host-header","web-cache-deception","file-upload","clickjack","csp","redirect"];

export default function Benchmark() {
  return (
    <main>
      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-16 pt-14 sm:pb-20 sm:pt-20">
          <div className="flex items-center gap-4" data-reveal="up">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">The benchmark</span>
          </div>
          <div className="mt-8 grid items-center gap-12 lg:grid-cols-[1fr_minmax(0,0.92fr)] lg:gap-16">
            <div>
              <h1 className="display text-[clamp(2.7rem,7vw,6rem)]" data-hero>
                <span className="block overflow-hidden"><span data-reveal="up" className="block">Measured.</span></span>
                <span className="block overflow-hidden">
                  <span data-reveal="up" data-delay="90" className="block">
                    <span className="text-outline">Not</span> <span className="text-brand">claimed.</span>
                  </span>
                </span>
              </h1>
              <Reveal as="p" delay={200} className="mt-8 max-w-[48ch] text-lg leading-relaxed text-fg/80">
                Every tool says it finds bugs. HUNTR gets <span className="font-semibold text-fg">graded</span> — against
                targets where the answers are already known. &ldquo;It works&rdquo; is a number, not a vibe.
              </Reveal>
            </div>
            <Reveal delay={200} className="w-full">
              <AttackCoverage />
            </Reveal>
          </div>
        </div>
      </section>

      {/* STATS */}
      <section className="border-b border-line bg-surface">
        <div className="site-wrap py-20 sm:py-28">
          <div className="grid gap-12 sm:grid-cols-3">
            <Reveal><Stat value={58} label="Vulnerability classes" sub="Hunted end-to-end — recon to validated report." tone="brand" /></Reveal>
            <Reveal delay={120}><Stat value={11} label="Specialist agents" sub="Recon, exploit, chaining, reporting — each a focused agent." tone="fg" /></Reveal>
            <Reveal delay={240}><Stat value={0} label="Auto-submissions" sub="You review and send. Every finding, every time." tone="green" /></Reveal>
          </div>
        </div>
      </section>

      {/* METHOD */}
      <section className="border-b border-line">
        <div className="site-wrap py-20 sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">The method</span>
            <h2 className="display mt-4 max-w-[20ch] text-[clamp(2rem,5vw,4rem)]">No grading <span className="text-brand">on a curve.</span></h2>
            <p className="mt-5 max-w-[52ch] text-lg text-fg/70">
              We don&apos;t estimate. HUNTR is run against known-vulnerable targets, so every hit can be
              checked against what&apos;s actually there — results, not a curated demo.
            </p>
          </Reveal>
          <div className="mt-14 grid gap-px overflow-hidden border border-line sm:grid-cols-2 lg:grid-cols-3" data-reveal-group>
            {suites.map(([s, h, p], i) => (
              <div key={h} className="lantern bg-surface p-7" data-lantern>
                <div className="flex items-center gap-3">
                  <span className="numeral text-xl text-brand">0{i + 1}</span>
                  <span className="label text-faint">{s}</span>
                </div>
                <h3 className="display mt-4 text-xl">{h}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted">{p}</p>
              </div>
            ))}
          </div>

          <Reveal className="mt-10 flex flex-wrap gap-2">
            {classes.map((c) => (<span key={c} className="label border border-line px-3 py-2 text-muted">{c}</span>))}
          </Reveal>

          <Reveal className="mt-12 max-w-[72ch] border-l-4 border-brand bg-surface p-6 text-fg/75">
            <span className="font-semibold text-fg">Straight talk:</span> HUNTR is pre-launch. These numbers are what
            the engine does on a controlled benchmark with certain ground truth — capability, not customer logos.
            Real disclosed findings land here as they&apos;re published. We&apos;d rather show you a reproducible
            benchmark than a wall of logos we haven&apos;t earned.
          </Reveal>
        </div>
      </section>

      {/* CTA */}
      <section className="bg-brand text-brand-ink">
        <div className="site-wrap py-24 text-center sm:py-28">
          <Reveal type="mask">
            <span className="label text-brand-ink/70">Early access</span>
            <h2 className="display mx-auto mt-6 max-w-[16ch] text-[clamp(2.4rem,6.5vw,5.5rem)] text-brand-ink">Put it on a real target.</h2>
          </Reveal>
          <Reveal delay={150} className="mx-auto mt-10 flex max-w-md justify-center">
            <Waitlist onAccent className="w-full" />
          </Reveal>
        </div>
      </section>
    </main>
  );
}
