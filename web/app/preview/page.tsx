import type { Metadata } from "next";
import { ReticleCursor } from "@/components/reticle-cursor";
import { InteractiveHunt } from "@/components/interactive-hunt";
import { SurfaceGraph3D } from "@/components/surface-graph-3d";

export const metadata: Metadata = {
  title: "Preview — Operator Console",
  robots: { index: false, follow: false },
};

const STATUS = [
  ["crit", "critical"],
  ["high", "high"],
  ["test", "testing"],
  ["val", "validated"],
];

export default function Preview() {
  return (
    <div className="reticle-scope">
      <ReticleCursor />

      {/* HUD telemetry strip */}
      <div className="hud scanline border-b border-line bg-surface2/60">
        <div className="site-wrap flex flex-wrap items-center gap-x-6 gap-y-1 py-2 text-[10.5px] uppercase tracking-[0.14em] text-muted">
          <span className="flex items-center gap-2 text-fg">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full" style={{ background: "var(--validated)" }} />
            operator online
          </span>
          <span>58 classes</span><span>11 agents</span>
          <span>0 auto-submits</span><span className="text-brand">scope-locked</span>
          <span className="ml-auto hidden sm:inline">huntr · fire-control v2</span>
        </div>
      </div>

      {/* HERO — playable hunt */}
      <section className="border-b border-line">
        <div className="site-wrap grid items-center gap-12 py-16 lg:grid-cols-[1fr_minmax(0,0.92fr)] lg:gap-16 lg:py-24">
          <div>
            <div className="flex items-center gap-4">
              <span className="h-2 w-2 bg-brand" />
              <span className="label text-muted">Operator console</span>
            </div>
            <h1 className="display mt-7 text-[clamp(2.8rem,8vw,6.5rem)] leading-[0.95]">
              Point it. <br /><span className="text-brand">Watch it hunt.</span>
            </h1>
            <p className="mt-7 max-w-[46ch] text-lg leading-relaxed text-fg/80">
              This isn&apos;t a video. Type a target, hit run, and watch HUNTR map the surface, test it class
              by class, drop the false positives, and draft the report — the real loop, in your hands.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-2">
              {STATUS.map(([c, l]) => (
                <span key={l} className={`chip ${c}`}>{l}</span>
              ))}
              <span className="hud text-[10px] uppercase tracking-[0.14em] text-faint">one language, every surface</span>
            </div>
          </div>
          <div className="w-full">
            <InteractiveHunt />
          </div>
        </div>
      </section>

      {/* SURFACE GRAPH — 3D orbit */}
      <section className="scanline border-b border-line bg-surface">
        <div className="site-wrap grid items-center gap-12 py-20 lg:grid-cols-[minmax(0,0.9fr)_1fr] lg:gap-16 lg:py-28">
          <div className="order-2 lg:order-1">
            <div className="rounded-2xl border border-brand/20 bg-bg/40 p-3 shadow-[0_40px_120px_-50px_rgba(167,139,250,0.4)]">
              <SurfaceGraph3D />
            </div>
          </div>
          <div className="order-1 lg:order-2">
            <span className="label text-muted">Live surface map</span>
            <h2 className="display mt-4 text-[clamp(2rem,5.5vw,4.5rem)] leading-[1.02]">
              The whole attack surface — <span className="text-brand">one living graph.</span>
            </h2>
            <p className="mt-6 max-w-[48ch] text-lg leading-relaxed text-fg/75">
              Every host, endpoint, and parameter becomes a node. Edges are the exploit chains HUNTR reasons
              about. Nodes light up as the hunt confirms them — critical in <span style={{ color: "var(--critical)" }}>red</span>,
              high in <span style={{ color: "var(--high)" }}>amber</span>, validated in <span style={{ color: "var(--validated)" }}>green</span>.
            </p>
            <p className="mt-5 hud text-[11px] uppercase tracking-[0.14em] text-faint">drag the graph to orbit it →</p>
          </div>
        </div>
      </section>

      {/* note */}
      <section>
        <div className="site-wrap py-16 text-center">
          <p className="hud text-[11px] uppercase tracking-[0.16em] text-faint">
            prototype · operator-console direction · not linked from the live site
          </p>
        </div>
      </section>
    </div>
  );
}
