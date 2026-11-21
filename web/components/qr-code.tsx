"use client";

import { useEffect, useRef } from "react";

// Renders a QR code client-side (so the TOTP secret never leaves the browser —
// we never send it to a third-party QR service). Loads the small qrcodejs lib
// from cdnjs on demand.
declare global {
  interface Window {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    QRCode?: any;
  }
}

let loader: Promise<void> | null = null;
function loadQrLib(): Promise<void> {
  if (typeof window === "undefined") return Promise.reject(new Error("no window"));
  if (window.QRCode) return Promise.resolve();
  if (loader) return loader;
  loader = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js";
    s.async = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("QR library failed to load"));
    document.head.appendChild(s);
  });
  return loader;
}

export function QRCode({ text, size = 184 }: { text: string; size?: number }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    loadQrLib()
      .then(() => {
        if (cancelled || !ref.current || !window.QRCode) return;
        ref.current.innerHTML = "";
        // eslint-disable-next-line no-new
        new window.QRCode(ref.current, {
          text,
          width: size,
          height: size,
          colorDark: "#0A0B0D",
          colorLight: "#ffffff",
          correctLevel: window.QRCode.CorrectLevel ? window.QRCode.CorrectLevel.M : 0,
        });
      })
      .catch(() => {
        if (ref.current) {
          ref.current.innerHTML =
            '<p style="font-size:12px;color:#8A909C;padding:8px">QR unavailable — use the manual key below.</p>';
        }
      });
    return () => {
      cancelled = true;
    };
  }, [text, size]);

  return <div ref={ref} className="inline-block rounded-md bg-white p-2" aria-label="Two-factor QR code" />;
}
