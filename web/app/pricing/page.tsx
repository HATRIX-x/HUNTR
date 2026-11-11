import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { MailLink } from "@/components/legal";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "Simple, flat pricing for HUNTR — the autonomous AI operator for bug bounty. One subscription for the software; you bring your own Anthropic API key. Monthly, yearly, and a founder plan.",
  alternates: { canonical: "/pricing/" },
  openGraph: {
    title: "HUNTR pricing — flat, bring-your-own-key",
    description:
      "One subscription for the HUNTR software. You bring your own Anthropic API key, so AI usage is billed to you directly by Anthropic.",
    url: "https://huntr.run/pricing",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
  robots: { index: true, follow: true },
};

const plans = [
  {
    name: "Founder",
    price: "$29",
    cadence: "/ month",
    note: "Limited first cohort — locked for life",
    highlight: true,
    features: [
      "Everything in Monthly",
      "Price locked for as long as you stay subscribed",
      "Direct line to the team building it",
      "Shapes what ships next",
    ],
  },
  {
    name: "Monthly",
    price: "$49",
    cadence: "/ month",
    note: "The full operator, billed monthly",
    highlight: false,
    features: [
      "The full autonomous hunt pipeline",
      "Surface mapping, testing, validation, report drafts",
      "Scope controls + human-gated submissions",
      "Cancel anytime",
    ],
  },
  {
    name: "Yearly",
    price: "$490",
    cadence: "/ year",
    note: "Two months free vs. monthly",
    highlight: false,
    features: [
      "Everything in Monthly",
      "Best value — about $41 / month",
      "One invoice a year",
      "Cancel anytime",
    ],
  },
];

const faqs = [
  [
    "What does the price include?",
    "Your subscription is for the HUNTR software — the autonomous hunt engine and operator UI. It does not include AI usage costs (see below).",
  ],
  [
    "Why do I need my own Anthropic API key?",
    "HUNTR runs on your own Anthropic API key, so AI usage is billed directly to you by Anthropic at their rates. This keeps your key and your hunt data on your machine, and means you only ever pay Anthropic for exactly what you use. Adding your key takes about a minute on first run.",
  ],
  [
    "Can I cancel anytime?",
    "Yes. Cancelling stops future renewals and your access runs to the end of the period you already paid for.",
  ],
  [
    "Do you offer refunds?",
    "Payments are generally non-refundable, but if you were charged in error, email us and we'll make it right. See the Terms of Service for details.",
  ],
  [
    "Who handles billing?",
    "Payments are processed securely by Creem, our merchant of record. We never store your card details.",
  ],
];

export default function Pricing() {
  return (
    <main>
      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-16 pt-16 text-center sm:pb-20 sm:pt-24">
          <div className="flex items-center justify-center gap-4" data-reveal="up">
            <span className="h-2 w-2 bg-brand" />
            <span className="label text-muted">Pricing</span>
          </div>
          <h1 className="display mx-auto mt-8 max-w-[16ch] text-[clamp(2.6rem,9vw,7rem)]" data-hero>
            One price. <span className="text-brand">Your key.</span>
          </h1>
          <Reveal as="p" delay={160} className="mx-auto mt-8 max-w-[56ch] text-lg leading-relaxed text-fg/80">
            A flat subscription for the HUNTR software. You bring your own Anthropic API key, so AI usage is
            billed directly to you — no markup, no surprises. No per-finding fees, ever.
          </Reveal>
        </div>
      </section>

      {/* PLANS */}
      <section className="bg-surface">
        <div className="site-wrap py-20 sm:py-24">
          <div className="grid gap-px overflow-hidden border border-line lg:grid-cols-3" data-reveal-group>
            {plans.map((p) => (
              <div
                key={p.name}
                className={`relative flex flex-col p-8 sm:p-10 ${
                  p.highlight ? "bg-surface2 ring-1 ring-brand" : "bg-surface"
                }`}
              >
                {p.highlight && (
                  <span className="label absolute right-6 top-6 bg-brand px-2 py-1 text-brand-ink">
                    Best value
                  </span>
                )}
                <h2 className="display text-2xl">{p.name}</h2>
                <div className="mt-6 flex items-end gap-2">
                  <span className="display text-5xl text-fg">{p.price}</span>
                  <span className="mb-1 text-muted">{p.cadence}</span>
                </div>
                <p className="mt-3 text-sm text-muted">{p.note}</p>
                <ul className="mt-8 grid gap-3 text-sm text-fg/80">
                  {p.features.map((f) => (
                    <li key={f} className="flex gap-3">
                      <span className="mt-[6px] h-1.5 w-1.5 shrink-0 bg-brand" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                <Link
                  href="/access/"
                  className={`mt-10 ${p.highlight ? "btn-brand" : "btn-outline"} w-full text-center`}
                >
                  Get started
                </Link>
              </div>
            ))}
          </div>

          {/* BYO-key callout */}
          <Reveal className="mt-12 max-w-[72ch] border-l-4 border-brand bg-surface p-6 text-fg/80">
            <span className="font-semibold text-fg">Bring your own key.</span> HUNTR uses your own Anthropic API
            key for all AI usage, billed to you directly by Anthropic at their rates. Your subscription covers the
            software; your key covers the compute. Your key and your hunt data never leave your machine.
          </Reveal>
          <Reveal className="mt-6 label text-faint">
            Prices in USD, exclusive of any applicable taxes. Billing by Creem, our merchant of record · Authorized targets only.
          </Reveal>
        </div>
      </section>

      {/* FAQ */}
      <section className="border-t border-line">
        <div className="site-wrap py-20 sm:py-24">
          <Reveal type="mask">
            <span className="label text-muted">Questions</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">
              Good to <span className="text-brand">know.</span>
            </h2>
          </Reveal>
          <div className="mt-12 grid gap-px overflow-hidden border border-line sm:grid-cols-2" data-reveal-group>
            {faqs.map(([q, a]) => (
              <div key={q} className="bg-surface p-8 sm:p-10">
                <h3 className="display text-xl">{q}</h3>
                <p className="mt-3 leading-relaxed text-muted">{a}</p>
              </div>
            ))}
          </div>
          <Reveal className="mt-12 flex flex-wrap items-center gap-4">
            <Link href="/access/" className="btn-brand">Request access</Link>
            <Link href="/terms/" className="btn-outline">Terms of Service</Link>
            <span className="label text-muted">Questions? <MailLink /></span>
          </Reveal>
        </div>
      </section>
    </main>
  );
}
