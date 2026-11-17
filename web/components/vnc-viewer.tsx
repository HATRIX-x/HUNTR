"use client";

import { useEffect, useRef, useState } from "react";
import { getToken, API_URL } from "@/lib/api";

// noVNC is loaded from a CDN at runtime (not bundled) — webpackIgnore keeps the
// Next build from trying to resolve the external URL. Use jsDelivr's /+esm build:
// the package's own lib/rfb.js is a CommonJS bundle (require/exports), which a
// native dynamic import() can't load ("require is not defined"), so the live view
// failed to initialise. /+esm is a true ES module whose default export is RFB.
const NOVNC_URL = "https://cdn.jsdelivr.net/npm/@novnc/novnc@1.5.0/+esm";

export function VncViewer({ huntId, onClose }: { huntId: string; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let rfb: { disconnect: () => void } | null = null;
    let cancelled = false;
    (async () => {
      try {
        const mod = await import(/* webpackIgnore: true */ NOVNC_URL);
        if (cancelled || !ref.current) return;
        const RFB = (mod as { default: new (t: Element, u: string, o?: object) => {
          viewOnly: boolean; scaleViewport: boolean;
          addEventListener: (e: string, f: () => void) => void; disconnect: () => void;
        } }).default;
        const token = getToken() ?? "";
        const wsBase = API_URL.replace(/^http/, "ws");
        const url = `${wsBase}/v1/hunts/${encodeURIComponent(huntId)}/vnc?token=${encodeURIComponent(token)}`;
        const r = new RFB(ref.current, url, { wsProtocols: ["binary"] });
        r.viewOnly = true;
        r.scaleViewport = true;
        r.addEventListener("disconnect", () => setErr("Live view disconnected."));
        rfb = r;
      } catch {
        setErr("Couldn't load the live view.");
      }
    })();
    return () => { cancelled = true; try { rfb?.disconnect(); } catch { /* no-op */ } };
  }, [huntId]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="enter fixed inset-0 z-[80] flex items-center justify-center bg-black/85 p-4 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Live hunt view"
    >
      <div
        className="brackets relative w-full max-w-5xl overflow-hidden rounded-xl border border-green/25 shadow-glow-live"
        style={{ ["--bracket" as string]: err ? "var(--faint)" : "var(--green)" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-line bg-surface2/95 px-4 py-2.5">
          {err ? (
            <span className="hud flex items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-faint">
              <span className="h-1.5 w-1.5 rounded-full bg-faint" /> signal lost
            </span>
          ) : (
            <span className="hud flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-green">
              <span className="live-dot" /> live · operator browser
            </span>
          )}
          <button type="button" onClick={onClose} className="label rounded-md px-2.5 py-1 text-muted transition-colors hover:bg-white/5 hover:text-fg">
            Close <span aria-hidden>✕</span>
          </button>
        </div>
        <div ref={ref} className="h-[70vh] w-full bg-black" />
        {err && (
          <p className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/90 to-transparent px-4 pb-4 pt-10 text-center text-sm text-muted">
            {err}
          </p>
        )}
      </div>
    </div>
  );
}
