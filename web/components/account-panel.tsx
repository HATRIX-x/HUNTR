"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { me, registerAgent, checkout, clearToken, getToken, ApiError, type Me, type AgentToken, type Profile } from "@/lib/api";
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
  { slug: "scout", name: "Scout", price: "$25", credits: "25 credits" },
  { slug: "stalk", name: "Stalk", price: "$100", credits: "115 credits" },
  { slug: "takedown", name: "Takedown", price: "$300", credits: "360 credits" },
];

// ── crafted icons (no emoji) ──────────────────────────────────────────────
function LockIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2.4" stroke="currentColor" strokeWidth="1.6" />
      <path d="M8 10.5V7.8A4 4 0 0 1 16 7.8v2.7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="12" cy="15.3" r="1.5" fill="currentColor" />
      <path d="M12 16.4v1.8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}
function KeyIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <circle cx="8" cy="8" r="4.2" stroke="currentColor" strokeWidth="1.6" />
      <path d="M11 11l8 8M16 16l2-2M18.5 18.5l2-2" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard blocked */
        }
      }}
      className={`label shrink-0 rounded-md border px-3 py-1.5 transition-colors ${done ? "border-green/40 text-green" : "border-line text-muted hover:border-brand hover:text-brand"}`}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

export function AccountPanel() {
  const [state, setState] = useState<"loading" | "ready" | "signedout">("loading");
  const [user, setUser] = useState<Me | null>(null);
  const [token, setToken] = useState<AgentToken | null>(null);
  const [provisioning, setProvisioning] = useState(false);
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

  const provision = async () => {
    setErr(null);
    setProvisioning(true);
    try {
      setToken(await registerAgent("default"));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't create an agent token.");
    } finally {
      setProvisioning(false);
    }
  };

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
          See all packs &amp; monthly plans
        </Link>
      </div>

      {/* ── connect your operator ── */}
      <div className="panel p-7 sm:p-8">
        <div className="flex items-center gap-3">
          <span className="icon-badge h-10 w-10 text-brand"><KeyIcon className="h-5 w-5" /></span>
          <h2 className="display text-xl text-fg">Connect your operator</h2>
        </div>
        <p className="mt-4 max-w-2xl text-sm leading-relaxed text-muted">
          HUNTR runs every hunt for you on our infrastructure — no API key, no setup. Generate an
          agent token to connect the operator to your account, so your hunts, findings, and funnel all
          sync here.
        </p>

        {!isPaid ? (
          <div className="tile-locked mt-6 flex flex-col items-center gap-4 rounded-xl px-6 py-8 text-center">
            <span className="icon-badge icon-badge-pulse h-12 w-12 text-brand">
              <LockIcon className="h-6 w-6" />
            </span>
            <div>
              <p className="label text-brand">Paid plan required</p>
              <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-muted">
                Load credits to start hunting — HUNTR runs every hunt for you, no API key or setup
                required.
              </p>
            </div>
            <Link href="/pricing/" className="btn-brand mt-1">Choose a plan</Link>
          </div>
        ) : !token ? (
          <button
            type="button"
            onClick={provision}
            disabled={provisioning}
            className="btn-brand mt-6 disabled:opacity-60"
          >
            {provisioning ? "Generating…" : "Generate agent token"}
          </button>
        ) : (
          <div className="mt-6 space-y-4">
            <div>
              <span className="label text-faint">Agent token — shown once</span>
              <div className="mt-2 flex items-center gap-3 rounded-lg border border-line bg-bg px-4 py-3">
                <code className="min-w-0 flex-1 break-all font-mono text-xs text-green">
                  {token.agent_token}
                </code>
                <Copy text={token.agent_token} />
              </div>
              <p className="mt-2 text-xs text-faint">
                Store it somewhere safe now — for security it isn&apos;t shown again. You can always
                generate a new one.
              </p>
            </div>
            <div>
              <span className="label text-faint">Then, in the HUNTR app</span>
              <div className="mt-2 flex items-center gap-3 rounded-lg border border-line bg-bg px-4 py-3">
                <code className="min-w-0 flex-1 break-all font-mono text-xs text-fg">
                  huntr link --token {token.agent_token}
                </code>
                <Copy text={`huntr link --token ${token.agent_token}`} />
              </div>
            </div>
          </div>
        )}
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
