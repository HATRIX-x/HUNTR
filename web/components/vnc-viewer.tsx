"use client";

import { useEffect, useRef, useState } from "react";
import { getToken, API_URL } from "@/lib/api";

// noVNC is loaded from a CDN at runtime (not bundled) — webpackIgnore keeps the
// Next build from trying to resolve the external URL. Use jsDelivr's /+esm build:
// the package's own lib/rfb.js is a CommonJS bundle (require/exports), which a
// native dynamic import() can't load ("require is not defined"), so the live view
// failed to initialise. /+esm is a true ES module whose default export is RFB.
const NOVNC_URL = "https://cdn.jsdelivr.net/npm/@novnc/novnc@1.5.0/+esm";

type Rfb = {
  viewOnly: boolean;
  scaleViewport: boolean;
  focusOnClick: boolean;
  addEventListener: (e: string, f: () => void) => void;
  disconnect: () => void;
  focus: () => void;
};

export type StreamPhase = "loading" | "connecting" | "live" | "lost";
type Phase = StreamPhase;

/** The live CDP browser stream. Renders inline when `embedded`, else as a modal.
 *  View-only by default — HUNTR is driving this browser; "Take control" flips the
 *  RFB to accept the viewer's clicks/keys (they reach the same Chrome the agent
 *  uses, so it's co-driving). `onControlChange` lets a parent react (e.g. warn).
 *
 *  `bare` renders only the stream surface (no chrome) for a parent that draws its
 *  own frame — the live-operation cockpit. In that mode pass `control` to drive
 *  input from outside, `onStatus` to follow the connection, and bump
 *  `reconnectSignal` to reconnect. */
export function VncViewer({
  huntId,
  onClose,
  embedded = false,
  onControlChange,
  bare = false,
  control: controlProp,
  onStatus,
  reconnectSignal = 0,
}: {
  huntId: string;
  onClose?: () => void;
  embedded?: boolean;
  onControlChange?: (inControl: boolean) => void;
  bare?: boolean;
  control?: boolean;
  onStatus?: (phase: StreamPhase) => void;
  reconnectSignal?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const rfbRef = useRef<Rfb | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [ownControl, setControl] = useState(false);
  const controlled = controlProp !== undefined;
  const control = controlled ? !!controlProp : ownControl;
  const [attempt, setAttempt] = useState(0); // bump to reconnect

  useEffect(() => { onStatus?.(phase); }, [phase, onStatus]);

  useEffect(() => {
    let cancelled = false;
    let rfb: Rfb | null = null;
    setPhase("connecting");
    (async () => {
      try {
        const mod = await import(/* webpackIgnore: true */ NOVNC_URL);
        if (cancelled || !ref.current) return;
        // jsDelivr's /+esm bundle nests the class as `default.default` (its own
        // `default` export is a namespace object, NOT the RFB constructor). Resolve
        // it defensively across shapes so a CDN re-bundle can't silently break the
        // live view — an unresolved constructor used to throw and show "signal lost".
        const m = mod as Record<string, unknown> & { default?: Record<string, unknown> };
        const RFB = [m.default?.default, m.default, (m as Record<string, unknown>).RFB]
          .find((x) => typeof x === "function") as (new (t: Element, u: string, o?: object) => Rfb) | undefined;
        if (!RFB) { if (!cancelled) setPhase("lost"); return; }
        const token = getToken() ?? "";
        const wsBase = API_URL.replace(/^http/, "ws");
        const url = `${wsBase}/v1/hunts/${encodeURIComponent(huntId)}/vnc?token=${encodeURIComponent(token)}`;
        const r = new RFB(ref.current, url, { wsProtocols: ["binary"] });
        r.viewOnly = true;
        r.scaleViewport = true;
        r.focusOnClick = false;
        r.addEventListener("connect", () => !cancelled && setPhase("live"));
        r.addEventListener("disconnect", () => !cancelled && setPhase("lost"));
        rfb = r;
        rfbRef.current = r;
      } catch {
        if (!cancelled) setPhase("lost");
      }
    })();
    return () => {
      cancelled = true;
      rfbRef.current = null;
      try { rfb?.disconnect(); } catch { /* no-op */ }
    };
  }, [huntId, attempt, reconnectSignal]);

  // apply control state to the live RFB whenever it changes
  useEffect(() => {
    const r = rfbRef.current;
    if (r && phase === "live") {
      r.viewOnly = !control;
      if (control) try { r.focus(); } catch { /* no-op */ }
    }
    if (!controlled) onControlChange?.(control);
  }, [control, phase, onControlChange, controlled]);

  // Esc closes a modal; if in control, Esc first releases control.
  useEffect(() => {
    if (!onClose && !control) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (control) {
        if (controlled) onControlChange?.(false);
        else setControl(false);
      } else onClose?.();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose, control, controlled, onControlChange]);

  const reconnect = () => { setPhase("connecting"); setAttempt((a) => a + 1); };

  if (bare) return <div ref={ref} className="h-full w-full" />;

  const bracket = phase === "lost" ? "var(--faint)" : control ? "var(--high)" : "var(--green)";

  const chrome = (
    <>
      <div className="flex items-center justify-between gap-3 border-b border-line bg-surface2/95 px-4 py-2.5">
        <span className="hud flex items-center gap-2 text-[11px] uppercase tracking-[0.16em]">
          {phase === "lost" ? (
            <><span className="h-1.5 w-1.5 rounded-full bg-faint" /><span className="text-faint">signal lost</span></>
          ) : phase === "live" ? (
            control ? (
              <><span className="h-1.5 w-1.5 rounded-full bg-high" /><span className="font-semibold text-high">you have control</span></>
            ) : (
              <><span className="live-dot" /><span className="font-semibold text-green">live · HUNTR is driving</span></>
            )
          ) : (
            <><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan" /><span className="text-muted">connecting…</span></>
          )}
        </span>
        <div className="flex items-center gap-1.5">
          {phase === "live" && (
            <button
              type="button"
              onClick={() => setControl((c) => !c)}
              className={`label rounded-md px-2.5 py-1 transition-colors ${control ? "bg-high/15 text-high hover:bg-high/25" : "text-muted hover:bg-white/5 hover:text-fg"}`}
              title={control ? "Stop sending your input to the hunt's browser" : "Send your clicks and keystrokes to the hunt's browser (you'll be co-driving with HUNTR)"}
            >
              {control ? "Release control" : "Take control"}
            </button>
          )}
          {phase === "lost" && (
            <button type="button" onClick={reconnect} className="label rounded-md px-2.5 py-1 text-muted transition-colors hover:bg-white/5 hover:text-fg">
              Reconnect
            </button>
          )}
          {onClose && (
            <button type="button" onClick={onClose} className="label rounded-md px-2.5 py-1 text-muted transition-colors hover:bg-white/5 hover:text-fg">
              Close <span aria-hidden>✕</span>
            </button>
          )}
        </div>
      </div>
      <div className={`relative w-full bg-black ${embedded ? "aspect-[16/10]" : "h-[70vh]"}`}>
        <div ref={ref} className="h-full w-full" />
        {phase !== "live" && (
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-2 text-center">
            {phase === "lost" ? (
              <p className="px-6 text-sm text-muted">
                No live view. HUNTR only streams while a hunt is actively running in its browser.
              </p>
            ) : (
              <p className="px-6 text-sm text-faint">Attaching to the operator browser…</p>
            )}
          </div>
        )}
        {control && phase === "live" && (
          <div className="pointer-events-none absolute bottom-0 inset-x-0 bg-gradient-to-t from-black/80 to-transparent px-4 pb-2.5 pt-8 text-center">
            <p className="hud text-[10.5px] uppercase tracking-[0.14em] text-high/90">
              your input is going to the live browser · Esc to release
            </p>
          </div>
        )}
      </div>
    </>
  );

  if (embedded) {
    return (
      <div
        className="brackets relative overflow-hidden rounded-xl border bg-surface"
        style={{ ["--bracket" as string]: bracket, borderColor: "color-mix(in srgb, var(--green) 22%, transparent)" }}
      >
        {chrome}
      </div>
    );
  }

  return (
    <div
      className="enter fixed inset-0 z-[80] flex items-center justify-center bg-black/85 p-4 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Live hunt view"
    >
      <div
        className="brackets relative w-full max-w-5xl overflow-hidden rounded-xl border shadow-glow-live"
        style={{ ["--bracket" as string]: bracket, borderColor: "color-mix(in srgb, var(--green) 25%, transparent)" }}
        onClick={(e) => e.stopPropagation()}
      >
        {chrome}
      </div>
    </div>
  );
}
