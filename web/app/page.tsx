import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { Marquee } from "@/components/marquee";
import { Stat } from "@/components/stat";
import { ZeroDayStat } from "@/components/zeroday-stat";
import { Waitlist } from "@/components/waitlist";
import { JsonLd } from "@/components/jsonld";
import { FireControl } from "@/components/fire-control";
import { AttackFunnel } from "@/components/attack-funnel";

const faqs = [
  { q: "What is HUNTR?", a: "HUNTR is an autonomous AI operator for bug bounty. You point it at a target you're authorized to test and it maps the attack surface, tests it, validates what it finds, and drafts the report. You review and submit." },
  { q: "Does HUNTR submit reports automatically?", a: "No. HUNTR never auto-submits. Every finding is a draft for you to review and submit. The judgment stays human." },
  { q: "How is it different from a vulnerability scanner?", a: "Scanners stop at surface signals and produce noise. HUNTR runs a real methodology end-to-end, validates each finding to drop false positives, and delivers report-ready vulnerabilities with reproduction and impact." },
  { q: "Does it only run against authorized targets?", a: "Yes. HUNTR only runs against targets you're authorized to test, and it respects program scope. It's a tool for authorized security research." },
];

const cells = [
  ["Coverage", "End-to-end hunt", "Maps the surface, tests it, and keeps going until coverage is real — not a one-shot scan."],
  ["Signal", "Validated, not noisy", "False positives are dropped before they reach you. You read a short list of real bugs."],
  ["Output", "Report-ready", "Reproduction and impact come drafted with each finding. Minutes to review, not hours to write."],
  ["Control", "You hold the trigger", "Nothing is auto-submitted. HUNTR only runs on targets you're authorized to test."],
];

export default function Home() {
  return (
    <main>
      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@graph": [
            { "@type": "SoftwareApplication", name: "HUNTR", applicationCategory: "SecurityApplication", operatingSystem: "Web, Linux, macOS", url: "https://huntr.run/", description: "HUNTR is an autonomous AI operator for bug bounty. It maps the attack surface, tests it, validates findings, and drafts the report. You review and submit — it never submits for you.", offers: { "@type": "Offer", price: "0", priceCurrency: "USD", availability: "https://schema.org/PreOrder" } },
            { "@type": "Organization", name: "HUNTR", url: "https://huntr.run/", logo: "https://huntr.run/og.png" },
            { "@type": "WebSite", name: "HUNTR", url: "https://huntr.run/" },
            { "@type": "FAQPage", mainEntity: faqs.map((f) => ({ "@type": "Question", name: f.q, acceptedAnswer: { "@type": "Answer", text: f.a } })) },
          ],
        }}
      />

      {/* HERO */}
      <section className="relative border-b border-line">
        <div className="site-wrap pb-16 pt-14 sm:pb-20 sm:pt-20">
          <div className="flex items-center gap-4" data-reveal="up">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">Autonomous AI · Bug bounty operator</span>
          </div>

          <div className="mt-8 grid items-center gap-12 lg:grid-cols-[1.02fr_minmax(0,0.98fr)] lg:gap-16">
            <div>
              <h1 className="display text-[clamp(2.7rem,6.4vw,5.6rem)]" data-hero>
                <span className="block overflow-hidden"><span data-reveal="up" className="block">Anyone can run a</span></span>
                <span className="block overflow-hidden"><span data-reveal="up" data-delay="80" className="block text-outline">scanner.</span></span>
                <span className="block overflow-hidden"><span data-reveal="up" data-delay="160" className="block">HUNTR runs <span className="text-brand">the hunt.</span></span></span>
              </h1>

              <Reveal as="p" delay={220} className="mt-8 max-w-[46ch] text-lg leading-relaxed text-fg/80">
                Point it at a target you&apos;re authorized to test. HUNTR maps the attack surface, tests it class by class,
                validates what&apos;s real, and drafts the report.{" "}
                <span className="font-semibold text-fg">You review and submit. It never submits for you.</span>
              </Reveal>

              <Reveal delay={300} className="mt-8">
                <Waitlist slot="hero" />
              </Reveal>

              <Reveal delay={360} className="mt-8 flex flex-wrap gap-x-8 gap-y-3 border-t border-line pt-6">
                {[["Report-ready findings", "brand"], ["Never auto-submits", "green"], ["Authorized targets only", "brand"]].map(([t, c]) => (
                  <span key={t} className="label text-muted">
                    <span className={`mr-2 ${c === "green" ? "text-green" : "text-brand"}`}>◆</span>
                    {t}
                  </span>
                ))}
              </Reveal>
            </div>

            <Reveal delay={200} className="w-full">
              <FireControl />
            </Reveal>
          </div>
        </div>
      </section>

      {/* MARQUEE */}
      <div className="border-b border-line bg-surface py-5">
        <Marquee items={["It hunts. You decide.", "Surface → report.", "Validated, never auto-submitted.", "Scanners flag. HUNTR proves.", "Authorized targets only."]} />
      </div>

      {/* PROOF */}
      <section className="border-b border-line">
        <div className="site-wrap py-20 sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">At a glance</span>
            <h2 className="display mt-4 max-w-[18ch] text-[clamp(2rem,5vw,4rem)]">
              Built to hunt. Measured against <span className="text-brand">ground truth.</span>
            </h2>
          </Reveal>
          <div className="mt-16 grid gap-12 sm:grid-cols-3">
            <Reveal delay={0}><Stat value={58} label="Vulnerability classes" sub="Hunted end-to-end — recon to validated report." tone="brand" /></Reveal>
            <Reveal delay={120}><Stat value={30} label="Ground-truth bugs" sub="Benchmarked against certain answers — not guessed." tone="fg" /></Reveal>
            <Reveal delay={240}><Stat value={0} label="Auto-submissions" sub="You review and send. Every finding, every time." tone="green" /></Reveal>
            <ZeroDayStat />
          </div>
        </div>
      </section>

      {/* STATEMENT */}
      <section className="border-b border-line bg-surface">
        <div className="site-wrap py-24 sm:py-32">
          <Reveal type="mask">
            <span className="label text-brand">Why HUNTR</span>
            <p className="display mt-8 max-w-[16ch] text-[clamp(2.4rem,6.4vw,5.6rem)]">
              Scanners give <span className="text-outline">noise.</span>
              <br />
              Hunters give <span className="text-brand">payouts.</span>
            </p>
          </Reveal>
          <div className="mt-16 grid gap-px overflow-hidden border border-line sm:grid-cols-2 lg:grid-cols-4" data-reveal-group>
            {cells.map(([k, h, p], i) => (
              <div key={h} className="lantern bg-surface2 p-8" data-lantern>
                <div className="label text-faint">0{i + 1} · {k}</div>
                <h3 className="display mt-5 text-2xl">{h}</h3>
                <p className="mt-3 text-sm leading-relaxed text-muted">{p}</p>
              </div>
            ))}
          </div>
          <Reveal className="mt-12 flex flex-wrap gap-4">
            <Link href="/platform" className="btn-brand" data-magnetic>See how it works</Link>
            <Link href="/benchmark" className="btn-outline">View the benchmark</Link>
          </Reveal>
        </div>
      </section>

      {/* FUNNEL */}
      <section className="overflow-hidden border-b border-line">
        <div className="site-wrap py-20 text-center sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">End to end</span>
            <h2 className="display mx-auto mt-4 max-w-[18ch] text-[clamp(2rem,5vw,4rem)]">
              Every finding, <span className="text-brand">traced to a single lock.</span>
            </h2>
            <p className="mx-auto mt-5 max-w-[54ch] text-lg text-fg/70">
              Dozens of tests across the surface converge into one short list of validated, report-ready vulnerabilities.
            </p>
          </Reveal>
          <div className="mt-6">
            <AttackFunnel />
          </div>
        </div>
      </section>

      {/* COMPARISON */}
      <section className="border-b border-line">
        <div className="site-wrap py-20 sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">Comparison</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">HUNTR vs. a scanner.</h2>
            <p className="mt-5 max-w-[52ch] text-lg text-fg/70">Same target, two very different outputs. A scanner flags; HUNTR hunts, validates, and writes it up.</p>
          </Reveal>
          <div className="mt-14 grid gap-8 lg:grid-cols-2">
            <Reveal className="border border-brand/40 bg-surface p-8 shadow-[0_0_0_1px_rgba(167,139,250,0.15),0_40px_120px_-60px_rgba(167,139,250,0.4)] sm:p-10">
              <div className="flex items-baseline justify-between">
                <h3 className="display text-3xl">HUNTR</h3>
                <span className="label bg-brand px-3 py-1 text-brand-ink">Operator</span>
              </div>
              <ul className="mt-8 space-y-4">
                {["Tests behavior, then validates every finding", "Drops false positives before they reach you", "Reproduction and impact drafted per finding", "Covers the surface to depth — not one-shot", "Never auto-submits — you review and send"].map((t) => (
                  <li key={t} className="flex gap-4 text-fg"><span className="mt-1 text-brand">→</span><span>{t}</span></li>
                ))}
              </ul>
              <Link href="/access" className="btn-brand mt-10 w-full" data-magnetic>Request access</Link>
            </Reveal>
            <Reveal delay={120} className="border border-line p-8 sm:p-10">
              <div className="flex items-baseline justify-between">
                <h3 className="display text-3xl text-muted">Traditional scanner</h3>
                <span className="label border border-line px-3 py-1 text-muted">Noise</span>
              </div>
              <ul className="mt-8 space-y-4">
                {["Stops at surface signals (200 OK, reflected param)", "Dumps everything — you sift the false positives", "No reproduction or impact — you write the report", "One-shot, shallow pass over the surface", "Flags without judgment — confirms nothing"].map((t) => (
                  <li key={t} className="flex gap-4 text-muted"><span className="mt-1">×</span><span>{t}</span></li>
                ))}
              </ul>
              <span className="btn mt-10 block w-full border border-line py-3 text-center text-faint">The status quo</span>
            </Reveal>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="border-b border-line bg-surface">
        <div className="site-wrap py-20 sm:py-28">
          <Reveal type="mask">
            <span className="label text-muted">FAQ</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">Questions, answered.</h2>
          </Reveal>
          <div className="mt-12 divide-y divide-line border-y border-line" data-reveal-group>
            {faqs.map((f) => (
              <div key={f.q} className="grid gap-2 py-8 md:grid-cols-[0.9fr_1.1fr] md:gap-10">
                <h3 className="display text-xl sm:text-2xl">{f.q}</h3>
                <p className="max-w-[56ch] leading-relaxed text-muted">{f.a}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FINAL CTA */}
      <section className="bg-brand text-brand-ink">
        <div className="site-wrap py-24 text-center sm:py-32">
          <Reveal type="mask">
            <span className="label text-brand-ink/70">Early access</span>
            <h2 className="display mx-auto mt-6 max-w-[14ch] text-[clamp(2.6rem,7vw,6rem)] text-brand-ink">
              Stop scanning. Start hunting.
            </h2>
          </Reveal>
          <Reveal delay={160}>
            <p className="mx-auto mt-6 max-w-[46ch] text-lg text-brand-ink/75">
              Request early access to HUNTR and we&apos;ll reach out when your spot opens.
            </p>
            <div className="mx-auto mt-10 flex max-w-md justify-center">
              <Waitlist onAccent slot="cta" className="w-full" />
            </div>
          </Reveal>
        </div>
      </section>
    </main>
  );
}
