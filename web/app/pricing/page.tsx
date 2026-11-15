import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { MailLink } from "@/components/legal";
import { HudStrip } from "@/components/hud-strip";
import { PricingPlans } from "@/components/pricing-plans";
import { HuntEstimator } from "@/components/hunt-estimator";
import { StartLink } from "@/components/start-link";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "Pay-as-you-go pricing for HUNTR — the autonomous AI operator for bug bounty. Load credits, HUNTR runs every hunt for you. No API key, no setup, no surprise bills: a hunt only ever spends the credits you've loaded.",
  alternates: { canonical: "/pricing/" },
  openGraph: {
    title: "HUNTR pricing — pay per hunt, fully managed",
    description:
      "Load credits and HUNTR runs the hunts for you. No key, no setup. You only ever spend what you load — a hunt stops when your balance runs out.",
    url: "https://huntr.run/pricing",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
  robots: { index: true, follow: true },
};

const faqs = [
  [
    "How does pricing work?",
    "You load credits and HUNTR runs the hunts for you — no API key, no setup, nothing to install. Each hunt uses credits based on how much work it actually takes, and you see an estimate before a single request goes out.",
  ],
  [
    "Will I ever get a surprise bill?",
    "Never. You can only ever spend the credits you've loaded. Every hunt meters its own usage live and stops the moment your balance runs out — you're never charged a cent more than you've put in.",
  ],
  [
    "How many hunts do credits buy?",
    "It depends on the target. A small hunt runs about 12 credits, a full program about 30, a large deep hunt about 75. You always see the estimate up front and only pay for what the hunt actually uses.",
  ],
  [
    "Do credits expire?",
    "No. Credits don't expire — buy a pack and use it whenever you hunt.",
  ],
  [
    "Do you offer refunds?",
    "Unused credits are refundable within 14 days. Promotional/bonus credits and credits already spent on a completed hunt are non-refundable. See the Terms of Service for details.",
  ],
  [
    "Who handles billing?",
    "Payments are processed securely by Creem, our merchant of record. We never see or store your card details.",
  ],
];

export default function Pricing() {
  return (
    <main>
      <HudStrip rail="managed · pay per hunt" />

      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-16 pt-16 text-center sm:pb-20 sm:pt-24">
          <div className="flex items-center justify-center gap-4" data-reveal="up">
            <span className="inline-flex items-center gap-2.5 rounded-full border border-line-2 bg-bg/50 py-1.5 pl-2.5 pr-3.5">
              <span className="h-1.5 w-1.5 rounded-full bg-brand shadow-[0_0_8px_var(--brand-a40)]" />
              <span className="label text-[10.5px] text-fg/80">Pricing</span>
            </span>
          </div>
          <h1 className="display mx-auto mt-8 max-w-[18ch] text-[clamp(2.6rem,9vw,7rem)]" data-hero>
            Only pay for what you <span className="text-grad">hunt.</span>
          </h1>
          <Reveal as="p" delay={160} className="mx-auto mt-8 max-w-[58ch] text-lg leading-relaxed text-fg/80">
            Load credits and HUNTR runs every hunt for you — no API key, no setup. A hunt only ever spends the
            credits you&apos;ve loaded, so there are no surprise bills. Ever.
          </Reveal>
          <Reveal delay={240} className="mx-auto mt-10 flex flex-wrap justify-center gap-4">
            <StartLink className="btn-grad" />
            <a href="#how" className="btn-outline">How credits work</a>
          </Reveal>
          <Reveal delay={320}>
            <p className="mt-6 inline-flex items-center gap-2 text-sm text-muted"><span className="live-dot !h-1.5 !w-1.5" /><span><span className="text-green">No subscription required.</span> Credits don&apos;t expire.</span></p>
          </Reveal>
        </div>
      </section>

      {/* LAUNCH OFFER */}
      <section className="relative border-y border-green/20 bg-green/[0.06]">
        <div className="site-wrap flex flex-wrap items-center justify-center gap-x-4 gap-y-1 py-3.5 text-center">
          <span className="statuspill text-green">Launch offer</span>
          <span className="text-sm font-semibold text-fg">First 100 hunters get <span className="text-green">double credits</span> on their first pack, up to 100 bonus credits.</span>
        </div>
      </section>

      {/* BUY — credit packs */}
      <section id="buy" className="scroll-mt-20 bg-surface">
        <div className="site-wrap py-20 sm:py-24">
          <PricingPlans />

          <div className="mt-10 grid gap-px overflow-hidden rounded-[14px] border border-line bg-line md:grid-cols-2">
            <div className="bg-surface p-7 sm:p-8">
              <h3 className="font-semibold text-fg">We run it for you.</h3>
              <p className="mt-2 leading-relaxed text-fg/70">
                No Anthropic key, no install, nothing to configure. HUNTR runs every hunt on our own
                infrastructure — you just load credits and point it at a target you&apos;re authorized to test.
              </p>
            </div>
            <div className="bg-surface p-7 sm:p-8">
              <h3 className="font-semibold text-fg">No surprise bills.</h3>
              <p className="mt-2 leading-relaxed text-fg/70">
                A hunt can only ever spend the credits in your balance. The moment it runs out, the hunt stops
                and hands you everything it found — you decide whether to top up and keep going.
              </p>
            </div>
          </div>
          <p className="mt-6 text-sm text-faint">
            Prices in USD, exclusive of any applicable taxes. Billing by Creem, our merchant of record. Authorized targets only.
          </p>
        </div>
      </section>

      {/* HOW CREDITS WORK — estimator */}
      <section id="how" className="border-t border-line">
        <div className="site-wrap py-20 sm:py-24">
          <Reveal type="mask">
            <h2 className="display max-w-[22ch] text-[clamp(2rem,5vw,4rem)]">Priced by the hunt.</h2>
            <p className="mt-5 max-w-[58ch] text-lg text-fg/70">
              HUNTR sizes the target during recon and shows you a credit estimate before it spends a thing. Then it
              meters usage live as it hunts — you only pay for the work that actually runs.
            </p>
          </Reveal>
          <div className="mt-12">
            <HuntEstimator />
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="border-t border-line bg-surface">
        <div className="site-wrap grid gap-10 py-20 sm:py-24 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-16">
          <div className="lg:sticky lg:top-28 lg:self-start">
            <h2 className="display text-[clamp(2rem,5vw,4rem)]">Good to know.</h2>
            <p className="mt-5 text-lg text-fg/70">Questions? <MailLink /></p>
            <div className="mt-8 flex flex-wrap gap-3">
              <StartLink className="btn-brand" />
              <Link href="/terms/" className="btn-outline">Terms of Service</Link>
            </div>
          </div>
          <div className="border-t border-line">
            {faqs.map(([q, a], i) => (
              <details key={q} className="faq-item" open={i === 0}>
                <summary><h3 className="text-lg font-semibold text-fg">{q}</h3></summary>
                <p className="max-w-[62ch] pb-6 leading-relaxed text-muted">{a}</p>
              </details>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
