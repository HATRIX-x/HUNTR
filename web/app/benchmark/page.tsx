import type { Metadata } from "next";
import { Reveal } from "@/components/reveal";
import { Stat } from "@/components/stat";
import { CtaBand } from "@/components/get-started";
import { AttackCoverage } from "@/components/attack-coverage";
import { HudStrip } from "@/components/hud-strip";

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

export default function Benchmark() {
  return (
    <main>
      <HudStrip rail="measured, not claimed" />
      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-16 pt-14 sm:pb-20 sm:pt-20">
          <div className="flex items-center gap-4" data-reveal="up">
            <span className="inline-flex items-center gap-2.5 rounded-full border border-line-2 bg-bg/50 py-1.5 pl-2.5 pr-3.5">
              <span className="h-1.5 w-1.5 rounded-full bg-brand shadow-[0_0_8px_var(--brand-a40)]" />
              <span className="label text-[10.5px] text-fg/80">The benchmark</span>
            </span>
          </div>
          <div className="mt-8 grid items-center gap-12 [&>*]:min-w-0 lg:grid-cols-[1fr_minmax(0,0.92fr)] lg:gap-16">
            <div>
              <h1 className="display text-[clamp(2.7rem,7vw,6rem)]" data-hero>
                <span className="block overflow-hidden"><span data-reveal="up" className="block">Measured.</span></span>
                <span className="block overflow-hidden">
                  <span data-reveal="up" data-delay="90" className="block">
                    <span className="text-outline">Not</span> <span className="text-grad">claimed.</span>
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
            <Reveal><Stat value={58} label="Vulnerability classes" sub="Hunted end-to-end, recon to validated report." tone="brand" /></Reveal>
            <Reveal delay={120}><Stat value={11} label="Specialist agents" sub="Recon, exploit, chaining, reporting — each a focused agent." tone="cyan" /></Reveal>
            <Reveal delay={240}><Stat value={0} label="Auto-submissions" sub="You review and send. Every finding, every time." tone="green" /></Reveal>
          </div>
        </div>
      </section>

      {/* METHOD */}
      <section className="border-b border-line">
        <div className="site-wrap py-20 sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">The method</span>
            <h2 className="display mt-4 max-w-[20ch] text-[clamp(2rem,5vw,4rem)]">No grading on a curve.</h2>
            <p className="mt-5 max-w-[52ch] text-lg text-fg/70">
              We don&apos;t estimate. HUNTR is run against known-vulnerable targets, so every hit can be
              checked against what&apos;s actually there — results, not a curated demo.
            </p>
          </Reveal>
          <div className="mt-14 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-3" data-reveal-group>
            {suites.map(([s, h, p]) => (
              <div key={h} className="lantern bg-surface p-7" data-lantern>
                <span className={`label ${s === "Scoring" ? "text-green" : "text-brand"}`}>{s}</span>
                <h3 className="display mt-4 text-xl">{h}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted">{p}</p>
              </div>
            ))}
          </div>

          <Reveal className="panel mt-14 max-w-[72ch] overflow-hidden p-6 pl-8 text-fg/75">
            <span className="absolute inset-y-0 left-0 w-[3px] bg-[image:var(--grad-brand-v)]" aria-hidden />
            <span className="font-semibold text-fg">Straight talk:</span> HUNTR is pre-launch. These numbers are what
            the engine does on a controlled benchmark with certain ground truth — capability, not customer logos.
            Real disclosed findings land here as they&apos;re published. We&apos;d rather show you a reproducible
            benchmark than a wall of logos we haven&apos;t earned.
          </Reveal>
        </div>
      </section>

      <CtaBand title="Put it on a real target." />
    </main>
  );
}
