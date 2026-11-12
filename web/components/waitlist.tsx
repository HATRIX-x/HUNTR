"use client";
import { useState } from "react";

// Formspree endpoint — submissions email you + appear in the Formspree dashboard.
const FORM_ENDPOINT = "https://formspree.io/f/xbgdqdgl";

const valid = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

// Record a signup conversion in Cloudflare Web Analytics via a virtual pageview.
// CF's beacon tracks SPA navigations, so pushing a dedicated path registers a
// "/signup-complete" pageview (= a conversion) for visitors who aren't blocking it;
// we restore the real URL right after so the address bar stays clean.
function markConversion() {
  try {
    const prev = window.location.pathname + window.location.search;
    window.history.pushState(null, "", "/signup-complete/");
    window.dispatchEvent(new PopStateEvent("popstate"));
    window.setTimeout(() => window.history.replaceState(null, "", prev), 1500);
  } catch {
    /* no-op */
  }
}

export function Waitlist({
  className = "",
  onAccent = false,
  slot = "",
}: {
  className?: string;
  onAccent?: boolean;
  /** which form instance, e.g. "hero" | "cta" — for per-signup attribution */
  slot?: string;
}) {
  const [email, setEmail] = useState("");
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    if (!valid(email.trim())) {
      setMsg({ text: "Enter a valid email address.", ok: false });
      return;
    }
    if (!FORM_ENDPOINT) {
      setMsg({ text: "Waitlist opens soon — follow for the launch.", ok: true });
      return;
    }
    setBusy(true);
    const path = typeof window !== "undefined" ? window.location.pathname : "";
    const source = `huntr.run${path}${slot ? `#${slot}` : ""}`;
    try {
      const r = await fetch(FORM_ENDPOINT, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.trim(),
          source,
          page: path || "/",
          slot: slot || "default",
          referrer: typeof document !== "undefined" ? document.referrer : "",
          _subject: `HUNTR early access — ${path || "/"}${slot ? ` (${slot})` : ""}`,
        }),
      });
      if (!r.ok) throw new Error();
      markConversion();
      setMsg({ text: "You're on the list. We'll be in touch.", ok: true });
      setEmail("");
    } catch {
      setMsg({ text: "Something went wrong — try again.", ok: false });
    } finally {
      setBusy(false);
    }
  };

  const border = onAccent ? "border-brand-ink/30" : "border-line-2";
  const input = onAccent ? "text-brand-ink placeholder:text-brand-ink/50" : "text-fg placeholder:text-faint";
  const btn = onAccent ? "!bg-brand-ink !text-brand" : "";
  const okColor = onAccent ? "text-brand-ink" : "text-green";

  return (
    <div className={className}>
      <form onSubmit={onSubmit} className={`flex max-w-md flex-col gap-0 border ${border} sm:flex-row`}>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@domain.com"
          aria-label="Email address"
          className={`w-full flex-1 bg-transparent px-4 py-3.5 font-sans text-sm outline-none ${input}`}
        />
        <button type="submit" disabled={busy} className={`btn-brand shrink-0 disabled:opacity-60 ${btn}`}>
          {busy ? "Sending…" : "Request access"}
        </button>
      </form>
      <p className={`mt-3 min-h-[18px] text-sm ${msg ? (msg.ok ? okColor : "text-muted") : ""}`} role="status">
        {msg?.text}
      </p>
    </div>
  );
}
