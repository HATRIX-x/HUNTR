"use client";

import { useState } from "react";
import { getToken, checkout, ApiError } from "@/lib/api";

// A pricing CTA. Logged in → start a Creem checkout for `plan` and redirect to
// the hosted checkout. Logged out → send to signup carrying the plan, so the
// signup flow can continue straight into checkout.
export function CheckoutButton({
  plan,
  className = "",
  children,
}: {
  plan: string;
  className?: string;
  children: React.ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const go = async () => {
    setErr(null);
    if (!getToken()) {
      window.location.assign(`/signup/?plan=${encodeURIComponent(plan)}`);
      return;
    }
    setBusy(true);
    try {
      const { checkout_url } = await checkout(plan);
      window.location.assign(checkout_url);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        window.location.assign(`/login/?plan=${encodeURIComponent(plan)}`);
        return;
      }
      setErr(e instanceof Error ? e.message : "Couldn't start checkout.");
      setBusy(false);
    }
  };

  return (
    <>
      <button type="button" onClick={go} disabled={busy} className={`${className}`}>
        {busy ? "Starting checkout…" : children}
      </button>
      {err && <p className="mt-2 text-center text-xs text-critical">{err}</p>}
    </>
  );
}
