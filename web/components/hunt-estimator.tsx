"use client";

import Link from "next/link";
import { useState } from "react";
import { HUNT_SIZES, PACKS, PLANS } from "@/components/pricing-plans";

// Works out what a month of hunting costs from the published hunt sizes, and
// which pack or plan covers it. Pure arithmetic on the page's own numbers.
export function HuntEstimator() {
  const [size, setSize] = useState(1);
  const [hunts, setHunts] = useState(3);
  const s = HUNT_SIZES[size];
  const need = s.credits * hunts;

  const top = PACKS[PACKS.length - 1];
  const pack = PACKS.find((p) => p.credits >= need);
  const n = pack ? 1 : Math.ceil(need / top.credits);
  const packFit = pack ?? top;
  const packCredits = packFit.credits * n;
  const plan = PLANS.find((p) => p.credits >= need);

  return (
    <div className="grid gap-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
      {/* inputs */}
      <div className="panel p-6 sm:p-8">
        <p className="text-sm font-semibold text-fg" id="est-size">How big is the target?</p>
        <div role="radiogroup" aria-labelledby="est-size" className="mt-4 grid gap-2.5">
          {HUNT_SIZES.map((h, i) => (
            <button
              key={h.key}
              type="button"
              role="radio"
              aria-checked={size === i}
              onClick={() => setSize(i)}
              className="size-row"
            >
              <span className="flex h-[26px] w-8 shrink-0 items-end gap-1" aria-hidden>
                {[0, 1, 2].map((b) => (
                  <span key={b} className={`w-2 rounded-sm ${b <= i ? "bg-cyan" : "bg-line-2"}`} style={{ height: 10 + b * 8 }} />
                ))}
              </span>
              <span className="min-w-0 flex-1 text-left">
                <span className="block font-semibold text-fg">{h.name}</span>
                <span className="mt-0.5 block text-sm leading-snug text-muted">{h.desc}</span>
              </span>
              <span className="shrink-0 font-mono text-sm font-semibold text-green tabular">~{h.credits} credits</span>
            </button>
          ))}
        </div>

        <div className="mt-8 flex items-baseline justify-between gap-4">
          <label htmlFor="est-hunts" className="text-sm font-semibold text-fg">How many hunts?</label>
          <output htmlFor="est-hunts" className="display text-2xl text-fg tabular">{hunts}</output>
        </div>
        <input
          id="est-hunts"
          type="range"
          min={1}
          max={20}
          step={1}
          value={hunts}
          onChange={(e) => setHunts(Number(e.target.value))}
          className="est-range mt-3 w-full"
          style={{ ["--fill" as string]: `${((hunts - 1) / 19) * 100}%` }}
        />
        <div className="mt-2 flex justify-between font-mono text-[11px] text-faint" aria-hidden>
          <span>1</span><span>10</span><span>20</span>
        </div>
      </div>

      {/* readout */}
      <div className="panel flex flex-col p-6 sm:p-8" aria-live="polite">
        <p className="text-sm text-muted">
          {hunts} {s.name.toLowerCase()} {hunts === 1 ? "hunt" : "hunts"} is about
        </p>
        <p className="mt-2 flex items-baseline gap-3">
          <span className="display text-[clamp(3.5rem,8vw,5.5rem)] text-cyan tabular">{need.toLocaleString()}</span>
          <span className="text-lg text-fg/70">credits</span>
        </p>

        <div className="mt-7 grid gap-px overflow-hidden rounded-lg border border-line bg-line">
          <div className="bg-surface p-4">
            <div className="flex items-baseline justify-between gap-3">
              <span className="text-sm text-muted">Pay as you go</span>
              <span className="font-semibold text-fg tabular">
                {n > 1 ? `${n} × ` : ""}{packFit.name} · ${(packFit.amount * n).toLocaleString()}
              </span>
            </div>
            <p className="mt-1 text-right text-sm text-green tabular">
              {packCredits.toLocaleString()} credits, {(packCredits - need).toLocaleString()} left over
            </p>
          </div>
          <div className="bg-surface p-4">
            <div className="flex items-baseline justify-between gap-3">
              <span className="text-sm text-muted">Monthly</span>
              <span className="font-semibold text-fg tabular">
                {plan ? `${plan.name} · $${plan.amount} / mo` : "Apex, topped up with a pack"}
              </span>
            </div>
            <p className="mt-1 text-right text-sm tabular">
              {plan ? (
                <span className="text-green">{plan.credits} credits a month, {plan.credits - need} roll over</span>
              ) : (
                <span className="text-muted">More than the 180 credits a month Apex includes</span>
              )}
            </p>
          </div>
        </div>

        <div className="flex-1" />
        <Link href="/signup/" className="btn-grad mt-7 w-full text-center">Get started</Link>
        <p className="mt-4 text-sm leading-relaxed text-muted">
          A typical figure, not a quote. HUNTR shows the real estimate for your target before it spends anything.
        </p>
      </div>
    </div>
  );
}
