"use client";

import Link from "next/link";
import { useState } from "react";
import { PriceCounter } from "@/components/price-counter";

// Typical hunt sizes, in credits — the same figures the estimator and FAQ use.
export const HUNT_SIZES = [
  { key: "light", name: "Light", desc: "One host, small surface — up to ~75 endpoints", credits: 12 },
  { key: "standard", name: "Standard", desc: "A full program — up to ~300 endpoints", credits: 30 },
  { key: "deep", name: "Deep", desc: "Large multi-host surface, chains + zero-day", credits: 75 },
] as const;

// One-time credit packs — the primary way to buy. 1 credit = $1 of hunting,
// with a volume bonus on the bigger packs.
export const PACKS = [
  { name: "Scout", amount: 25, credits: 25, bonus: 0, note: "Get eyes on the target — a couple of hunts", tag: "" },
  { name: "Stalk", amount: 100, credits: 115, bonus: 15, note: "The pack most hunters start with", tag: "Most popular" },
  { name: "Takedown", amount: 300, credits: 360, bonus: 20, note: "The lowest price per credit", tag: "Best rate" },
];

// Optional monthly plans for regulars — a better standing rate, credits roll over.
export const PLANS = [
  { name: "Hunter", amount: 49, credits: 55, bonus: 0, note: "For regulars — better rate, credits roll over", tag: "" },
  { name: "Apex", amount: 149, credits: 180, bonus: 0, note: "Always-on — the best standing rate", tag: "Best rate" },
];

type Offer = (typeof PACKS)[number];

function Card({ o, monthly, featured, max }: { o: Offer; monthly: boolean; featured: boolean; max: number }) {
  const rate = (o.amount / o.credits).toFixed(2);
  const base = monthly ? o.credits : o.amount; // packs: $1 buys 1 base credit, the rest is bonus
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
        <span className="mb-1.5 text-sm text-muted">{monthly ? "/ month" : "one-time"}</span>
      </div>

      {/* credit meter — width is this offer's credits against the biggest in the row */}
      <div className="mt-7">
        <div className="flex items-baseline justify-between gap-3">
          <span className="text-base font-semibold text-green tabular">
            {o.credits} credits{monthly ? " / mo" : ""}
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
      <Link href="/signup/" className={`mt-8 ${featured ? "btn-grad" : "btn-outline"} w-full text-center`}>
        {monthly ? `Choose ${o.name}` : "Buy credits"}
      </Link>
    </div>
  );
}

export function PricingPlans() {
  const [mode, setMode] = useState<"packs" | "monthly">("packs");
  const monthly = mode === "monthly";

  return (
    <div>
      <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h2 className="display text-[clamp(2rem,5vw,4rem)]">
            {monthly ? (
              <>Hunting a lot? <span className="text-green">Lock a better rate.</span></>
            ) : (
              "Load up and hunt."
            )}
          </h2>
          <p className="mt-5 max-w-[58ch] text-lg text-fg/70">
            {monthly
              ? "Optional monthly plans for regulars — a lower price per credit and unused credits roll over while you're subscribed. Cancel anytime; pure pay-as-you-go stays available too."
              : "One credit is one dollar of hunting. Buy a pack whenever you need it — the bigger the pack, the more bonus credits you get. No subscription required."}
          </p>
        </div>

        <div role="tablist" aria-label="How you want to pay" className="seg shrink-0 self-start lg:self-auto" data-on={monthly ? "1" : "0"}>
          <span className="seg-thumb" aria-hidden />
          <button type="button" role="tab" id="tab-packs" aria-controls="panel-packs" aria-selected={!monthly} onClick={() => setMode("packs")}>
            Pay as you go
          </button>
          <button type="button" role="tab" id="tab-monthly" aria-controls="panel-monthly" aria-selected={monthly} onClick={() => setMode("monthly")}>
            Monthly
          </button>
        </div>
      </div>

      <div id="panel-packs" role="tabpanel" aria-labelledby="tab-packs" hidden={monthly} className={`mt-12 items-stretch gap-5 lg:grid-cols-3 ${monthly ? "hidden" : "grid"}`}>
        {PACKS.map((p) => (
          <Card key={p.name} o={p} monthly={false} featured={p.name === "Stalk"} max={360} />
        ))}
      </div>
      <div id="panel-monthly" role="tabpanel" aria-labelledby="tab-monthly" hidden={!monthly} className={`mt-12 items-stretch gap-5 md:grid-cols-2 ${monthly ? "grid" : "hidden"}`}>
        {PLANS.map((p) => (
          <Card key={p.name} o={p} monthly featured={false} max={180} />
        ))}
      </div>
    </div>
  );
}
