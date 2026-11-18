"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { me, checkout, clearToken, getToken, ApiError, type Me, type Profile } from "@/lib/api";
import { TwoFactor } from "@/components/two-factor";
import { Onboarding } from "@/components/onboarding";
import { ProfileSettings } from "@/components/profile-settings";
import { ChangePassword } from "@/components/change-password";

// internal plan slug → customer-facing label
const PLAN_LABELS: Record<string, string> = {
  free: "Free",
  hunter: "Hunter",
  apex: "Apex",
  // legacy tiers (pre-credits)
  founder: "Day Zero",
  monthly: "Operator",
  yearly: "Overwatch",
};

// Credit packs offered in-account (slug must match the backend / Creem product).
const CREDIT_PACKS = [
  { slug: "scout", name: "Scout", price: "$30", credits: "30 credits" },
  { slug: "stalk", name: "Stalk", price: "$100", credits: "115 credits" },
  { slug: "takedown", name: "Takedown", price: "$300", credits: "360 credits" },
];

export function AccountPanel() {
  const [state, setState] = useState<"loading" | "ready" | "signedout">("loading");
  const [user, setUser] = useState<Me | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [buying, setBuying] = useState<string | null>(null);

  const buyPack = async (slug: string) => {
    setErr(null);
    setBuying(slug);
    try {
      const { checkout_url } = await checkout(slug);
      window.location.assign(checkout_url);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't start checkout.");
      setBuying(null);
    }
  };

  useEffect(() => {
    if (!getToken()) {
      setState("signedout");
      return;
    }
    me()
      .then((u) => {
        setUser(u);
        setState("ready");
      })
      .catch((e) => {
        if (e instanceof ApiError && (e.status === 401 || e.status === 404)) {
          clearToken();
          setState("signedout");
        } else {
          setErr(e instanceof Error ? e.message : "Couldn't load your account.");
          setState("ready");
        }
      });
  }, []);

  const signOut = () => {
    clearToken();
    window.location.assign("/login/");
  };

  if (state === "loading") {
    return (
      <div className="panel flex items-center gap-3 p-8">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-line border-t-brand" />
        <p className="text-sm text-muted">Loading your account…</p>
      </div>
    );
  }

  if (state === "signedout") {
    return (
      <div className="panel p-8 sm:p-10">
        <h1 className="display text-2xl text-fg">You&apos;re signed out</h1>
        <p className="mt-3 text-sm text-muted">Sign in or create an account to continue.</p>
        <div className="mt-6 flex gap-3">
          <Link href="/login/" className="btn-brand">Sign in</Link>
          <Link href="/signup/" className="btn-outline">Create account</Link>
        </div>
      </div>
    );
  }

  // First-run onboarding — collect a few profile details before the account proper.
  if (user && user.onboarded === false) {
    return (
      <Onboarding
        email={user.email}
        onDone={(p: Profile) => setUser((u) => (u ? { ...u, onboarded: true, profile: p } : u))}
      />
    );
  }

  const plan = user?.plan ?? "free";
  const isPaid = plan !== "free";
  const planLabel = PLAN_LABELS[plan] ?? plan;
  const monogram = (user?.email?.[0] ?? "?").toUpperCase();

  return (
    <div className="space-y-5">
      {/* ── identity header ── */}
      <div className="panel brackets flex flex-wrap items-start justify-between gap-5 p-7 sm:p-8">
        <div className="flex min-w-0 items-center gap-4">
          <div className="grid h-14 w-14 shrink-0 place-items-center rounded-xl bg-grad-brand text-xl font-bold text-brand-ink shadow-glow-brand">
            {monogram}
          </div>
          <div className="min-w-0">
            <span className="label text-faint">Account</span>
            <h1 className="display mt-1 truncate text-2xl text-fg sm:text-[26px]">{user?.email}</h1>
            <div className="mt-2.5">
              <span className={`statuspill ${isPaid ? "text-green" : "text-faint"}`}>
                <span className="dot" />
                {isPaid ? planLabel : "Free plan"}
              </span>
            </div>
          </div>
        </div>
        <div className="flex shrink-0 gap-2.5">
          {!isPaid && <Link href="/pricing/" className="btn-brand">Upgrade</Link>}
          <button type="button" onClick={signOut} className="btn-outline">Sign out</button>
        </div>
      </div>

      {err && (
        <div role="alert" className="enter rounded-lg border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">
          {err}
        </div>
      )}

      {/* ── credits balance + buy ── */}
      <div className="panel overflow-hidden p-7 sm:p-8">
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: "radial-gradient(70% 120% at 0% 0%, var(--green-a06), transparent 60%)" }}
          aria-hidden
        />
        <div className="relative flex flex-wrap items-end justify-between gap-4">
          <div>
            <span className="label flex items-center gap-2 text-faint"><span className="live-dot !h-1.5 !w-1.5" />Credit balance</span>
            <p className="mt-2 flex items-baseline gap-2">
              <span className="numeral text-5xl text-green">{(user?.credits ?? 0).toLocaleString()}</span>
              <span className="text-sm text-muted">credits</span>
            </p>
          </div>
          <p className="max-w-xs text-sm leading-relaxed text-muted">
            Credits run your hunts — a hunt only ever spends what you&apos;ve loaded. Top up below.
          </p>
        </div>
        <div className="relative mt-6 grid gap-3 sm:grid-cols-3">
          {CREDIT_PACKS.map((p) => (
            <div key={p.slug} className="lantern flex flex-col gap-1 rounded-[10px] border border-line bg-bg/50 p-5 transition-colors duration-300 hover:border-green/30" data-lantern>
              <span className="display text-lg text-fg">{p.name}</span>
              <span className="text-sm font-semibold text-green">{p.credits}</span>
              <button
                type="button"
                onClick={() => buyPack(p.slug)}
                disabled={buying !== null}
                className="btn-live btn-sm mt-3 w-full"
              >
                {buying === p.slug ? "Starting…" : `Buy · ${p.price}`}
              </button>
            </div>
          ))}
        </div>
        <Link href="/pricing/" className="relative mt-5 inline-block label ulink text-muted hover:text-fg">
          See all packs
        </Link>
      </div>

      <TwoFactor enabled={!!user?.twofa_enabled} />

      <ChangePassword />

      <ProfileSettings
        initial={user?.profile ?? {}}
        onSaved={(p) => setUser((u) => (u ? { ...u, profile: p } : u))}
      />
    </div>
  );
}
