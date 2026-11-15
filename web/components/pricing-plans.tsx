"use client";

import { PriceCounter } from "@/components/price-counter";
import { CheckoutButton } from "@/components/checkout-button";

// Typical hunt sizes, in credits — the same figures the estimator and FAQ use.
export const HUNT_SIZES = [
  { key: "light", name: "Light", desc: "One host, small surface — up to ~75 endpoints", credits: 12 },
  { key: "standard", name: "Standard", desc: "A full program — up to ~300 endpoints", credits: 30 },
  { key: "deep", name: "Deep", desc: "Large multi-host surface, chains + zero-day", credits: 75 },
] as const;

// One-time credit packs — the primary way to buy. 1 credit = $1 of hunting,
// with a volume bonus on the bigger packs.
export const PACKS = [
  { name: "Scout", amount: 30, credits: 30, bonus: 0, note: "Get eyes on the target — one standard hunt, or a couple of light ones", tag: "" },
  { name: "Stalk", amount: 100, credits: 115, bonus: 15, note: "The pack most hunters start with", tag: "Most popular" },
  { name: "Takedown", amount: 300, credits: 360, bonus: 20, note: "The lowest price per credit", tag: "Best rate" },
];

type Offer = (typeof PACKS)[number];

function Card({ o, featured, max }: { o: Offer; featured: boolean; max: number }) {
  const rate = (o.amount / o.credits).toFixed(2);
  const base = o.amount; // $1 buys 1 base credit, the rest is bonus
  return (
    <div
      data-lantern
      className={`pricing-card lantern relative flex flex-col rounded-[14px] border p-7 sm:p-8 ${
        featured ? "pricing-featured border-brand/40 bg-surface2 shadow-glow-brand" : "border-line bg-bg/40"
      }`}
    >
      <div className="flex min-h-[26px] items-center justify-between gap-3">
        <h3 className="display text-2xl">{o.name}</h3>
        {o.tag && <span className={featured ? "verified" : "chip info"}>{o.tag}</span>}
      </div>

      <div className="mt-7 flex items-end gap-2">
        <PriceCounter value={o.amount} className="display text-6xl text-fg" />
        <span className="mb-1.5 text-sm text-muted">one-time</span>
      </div>

      {/* credit meter — width is this offer's credits against the biggest in the row */}
      <div className="mt-7">
        <div className="flex items-baseline justify-between gap-3">
          <span className="text-base font-semibold text-green tabular">
            {o.credits} credits
          </span>
          {o.bonus > 0 && <span className="text-sm font-semibold text-green">+{o.bonus}% bonus</span>}
        </div>
        <div className="credit-meter mt-2.5" aria-hidden>
          <span style={{ width: `${(base / max) * 100}%` }} className="credit-meter-base" />
          {o.credits > base && <span style={{ width: `${((o.credits - base) / max) * 100}%` }} className="credit-meter-bonus" />}
        </div>
        <p className="mt-2.5 font-mono text-xs text-muted tabular">${rate} per credit</p>
      </div>

      <p className="mt-5 text-sm leading-relaxed text-fg/70">{o.note}</p>

      <dl className="mt-6 grid grid-cols-3 gap-px overflow-hidden rounded-lg border border-line bg-line text-center">
        {HUNT_SIZES.map((s) => {
          const n = Math.floor(o.credits / s.credits);
          return (
            <div key={s.key} className="bg-surface px-2 py-3">
              <dd className={`display text-xl tabular ${n ? "text-fg" : "text-faint"}`}>{n ? `~${n}` : "—"}</dd>
              <dt className="mt-1 text-[11px] text-muted">{s.name.toLowerCase()} hunts</dt>
            </div>
          );
        })}
      </dl>

      <div className="flex-1" />
      <div className="mt-8">
        <CheckoutButton plan={o.name.toLowerCase()} className={`${featured ? "btn-grad" : "btn-outline"} w-full text-center`}>
          Buy credits
        </CheckoutButton>
      </div>
    </div>
  );
}

export function PricingPlans() {
  return (
    <div>
      <h2 className="display text-[clamp(2rem,5vw,4rem)]">Load up and hunt.</h2>
      <p className="mt-5 max-w-[58ch] text-lg text-fg/70">
        One credit is one dollar of hunting. Buy a pack whenever you need it — the bigger the pack, the more
        bonus credits you get. No subscription required.
      </p>
      <div className="mt-12 grid items-stretch gap-5 lg:grid-cols-3">
        {PACKS.map((p) => (
          <Card key={p.name} o={p} featured={p.name === "Stalk"} max={360} />
        ))}
      </div>
    </div>
  );
}
