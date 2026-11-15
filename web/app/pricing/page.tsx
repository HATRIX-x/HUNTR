import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { MailLink } from "@/components/legal";
import { HudStrip } from "@/components/hud-strip";
import { PriceCounter } from "@/components/price-counter";

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

// One-time credit packs — the primary way to buy. 1 credit = $1 of hunting,
// with a volume bonus on the bigger packs.
const packs = [
  {
    name: "Scout",
    amount: 25,
    credits: "25 credits",
    note: "Get eyes on the target — a couple of hunts",
    highlight: false,
  },
  {
    name: "Stalk",
    amount: 100,
    credits: "115 credits",
    note: "+15% bonus · most popular",
    highlight: true,
  },
  {
    name: "Takedown",
    amount: 300,
    credits: "360 credits",
    note: "+20% bonus · best rate",
    highlight: false,
  },
];

// Optional monthly plans for regulars — a better standing rate, credits roll over.
const plans = [
  { name: "Hunter", amount: 49, credits: "55 credits / mo", note: "For regulars — better rate, credits roll over" },
  { name: "Apex", amount: 149, credits: "180 credits / mo", note: "Always-on — the best standing rate" },
];

// What a hunt typically costs — HUNTR sizes the surface during recon and shows
// you the estimate before it spends anything.
const sizes = [
  ["Light", "One host, small surface — up to ~75 endpoints", "~12 credits"],
  ["Standard", "A full program — up to ~300 endpoints", "~30 credits"],
  ["Deep", "Large multi-host surface, chains + zero-day", "~75 credits"],
];

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
    "Pay-as-you-go credits don't expire. On a monthly plan, unused credits roll over for as long as you stay subscribed.",
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
            <Link href="/signup/" className="btn-grad" data-magnetic>Start free</Link>
            <a href="#how" className="btn-outline">How credits work</a>
          </Reveal>
          <Reveal delay={320}>
            <p className="mt-6 inline-flex items-center gap-2 text-sm text-muted"><span className="live-dot !h-1.5 !w-1.5" /><span><span className="text-green">First hunt&apos;s on us.</span> No commitment.</span></p>
          </Reveal>
        </div>
      </section>

      {/* LAUNCH OFFER */}
      <section className="relative border-y border-green/20 bg-green/[0.06]">
        <div className="site-wrap flex flex-wrap items-center justify-center gap-x-4 gap-y-1 py-3.5 text-center">
          <span className="statuspill text-green">Launch offer</span>
          <span className="text-sm font-semibold text-fg">First 100 hunters get <span className="text-green">double credits</span> on their first pack.</span>
        </div>
      </section>

      {/* CREDIT PACKS */}
      <section className="bg-surface">
        <div className="site-wrap py-20 sm:py-24">
          <Reveal type="mask">
            <span className="label text-muted">Credits</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">
              Load up and hunt.
            </h2>
            <p className="mt-5 max-w-[54ch] text-lg text-fg/70">
              One credit is one dollar of hunting. Buy a pack whenever you need it — the bigger the pack, the more
              bonus credits you get. No subscription required.
            </p>
          </Reveal>

          <div className="mt-14 grid items-stretch gap-5 lg:grid-cols-3" data-reveal-group>
            {packs.map((p) => (
              <div
                key={p.name}
                data-lantern
                className={`pricing-card lantern relative flex flex-col rounded-xl border p-8 sm:p-10 ${
                  p.highlight ? "pricing-featured border-brand/40 bg-surface2 shadow-glow-brand" : "border-line bg-bg/40"
                }`}
              >
                {p.highlight && (
                  <span className="verified absolute right-6 top-6">Best value</span>
                )}
                <h3 className="display text-2xl">{p.name}</h3>
                <div className="mt-6 flex items-end gap-2">
                  <PriceCounter value={p.amount} className="display text-5xl text-fg" />
                </div>
                <p className="mt-3 text-sm font-semibold text-green">{p.credits}</p>
                <p className="mt-1 text-sm text-muted">{p.note}</p>
                <div className="flex-1" />
                <Link
                  href="/signup/"
                  className={`mt-10 ${p.highlight ? "btn-grad" : "btn-outline"} w-full text-center`}
                >
                  Buy credits
                </Link>
              </div>
            ))}
          </div>

          {/* Managed callout — replaces the old BYO-key callout */}
          <Reveal className="panel mt-12 max-w-[72ch] overflow-hidden p-6 pl-8 text-fg/80">
            <span className="absolute inset-y-0 left-0 w-[3px] bg-[image:var(--grad-brand-v)]" aria-hidden />
            <span className="font-semibold text-fg">We run it for you.</span> No Anthropic key, no install, nothing
            to configure. HUNTR runs every hunt on our own infrastructure — you just load credits and point it at a
            target you&apos;re authorized to test. Each hunt meters its own usage and stops at your balance, so you
            can never be charged more than you&apos;ve loaded.
          </Reveal>
          <Reveal className="mt-6 label text-faint">
            Prices in USD, exclusive of any applicable taxes. Billing by Creem, our merchant of record · Authorized targets only.
          </Reveal>
        </div>
      </section>

      {/* HOW CREDITS WORK */}
      <section id="how" className="border-t border-line">
        <div className="site-wrap py-20 sm:py-24">
          <Reveal type="mask">
            <span className="label text-muted">How credits work</span>
            <h2 className="display mt-4 max-w-[22ch] text-[clamp(2rem,5vw,4rem)]">
              Priced by the hunt.
            </h2>
            <p className="mt-5 max-w-[56ch] text-lg text-fg/70">
              HUNTR sizes the target during recon and shows you a credit estimate before it spends a thing. Then it
              meters usage live as it hunts — you only pay for the work that actually runs.
            </p>
          </Reveal>

          <div className="mt-14 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-3" data-reveal-group>
            {sizes.map(([name, desc, cost], i) => (
              <div key={name} className="lantern bg-surface p-8 sm:p-10" data-lantern>
                <div className="flex items-end gap-1.5" aria-hidden>
                  {[0, 1, 2].map((b) => (
                    <span key={b} className={`w-2 rounded-sm ${b <= i ? "bg-brand" : "bg-line-2"}`} style={{ height: 10 + b * 8 }} />
                  ))}
                </div>
                <h3 className="display mt-6 text-2xl">{name}</h3>
                <p className="mt-3 leading-relaxed text-muted">{desc}</p>
                <p className="mt-5 font-mono text-sm font-semibold text-green">{cost}</p>
              </div>
            ))}
          </div>

          <Reveal className="panel mt-12 max-w-[64ch] overflow-hidden p-6 pl-8 text-fg/75">
            <span className="absolute inset-y-0 left-0 w-[3px] bg-[image:var(--grad-brand-v)]" aria-hidden />
            <span className="font-semibold text-fg">No surprise bills.</span> A hunt can only ever spend the credits
            in your balance. The moment it runs out, the hunt stops and hands you everything it found — you decide
            whether to top up and keep going.
          </Reveal>
        </div>
      </section>

      {/* MONTHLY PLANS */}
      <section className="bg-surface">
        <div className="site-wrap py-20 sm:py-24">
          <Reveal type="mask">
            <span className="label text-muted">Subscribe &amp; save</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">
              Hunting a lot? <span className="text-green">Lock a better rate.</span>
            </h2>
            <p className="mt-5 max-w-[54ch] text-lg text-fg/70">
              Optional monthly plans for regulars — a lower price per credit and unused credits roll over while
              you&apos;re subscribed. Cancel anytime; pure pay-as-you-go stays available too.
            </p>
          </Reveal>

          <div className="mt-14 grid gap-5 sm:grid-cols-2 lg:max-w-3xl" data-reveal-group>
            {plans.map((p) => (
              <div key={p.name} data-lantern className="pricing-card lantern flex flex-col rounded-xl border border-line bg-bg/40 p-8 sm:p-10">
                <h3 className="display text-2xl">{p.name}</h3>
                <div className="mt-6 flex items-end gap-2">
                  <PriceCounter value={p.amount} className="display text-5xl text-fg" />
                  <span className="mb-1 text-muted">/ month</span>
                </div>
                <p className="mt-3 text-sm font-semibold text-green">{p.credits}</p>
                <p className="mt-1 text-sm text-muted">{p.note}</p>
                <Link href="/signup/" className="btn-outline mt-10 w-full text-center">
                  Choose {p.name}
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="border-t border-line">
        <div className="site-wrap py-20 sm:py-24">
          <Reveal type="mask">
            <span className="label text-muted">Questions</span>
            <h2 className="display mt-4 text-[clamp(2rem,5vw,4rem)]">
              Good to know.
            </h2>
          </Reveal>
          <div className="mt-12 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2" data-reveal-group>
            {faqs.map(([q, a]) => (
              <div key={q} className="bg-surface p-8 sm:p-10">
                <h3 className="display text-xl">{q}</h3>
                <p className="mt-3 leading-relaxed text-muted">{a}</p>
              </div>
            ))}
          </div>
          <Reveal className="mt-12 flex flex-wrap items-center gap-4">
            <Link href="/signup/" className="btn-brand">Start free</Link>
            <Link href="/terms/" className="btn-outline">Terms of Service</Link>
            <span className="label text-muted">Questions? <MailLink /></span>
          </Reveal>
        </div>
      </section>
    </main>
  );
}
