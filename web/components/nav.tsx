"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect, useRef } from "react";
import { BrandMark } from "@/components/brand-mark";
import { getToken, clearToken, me, ApiError, type Me } from "@/lib/api";

const links = [
  { href: "/platform", label: "Platform" },
  { href: "/benchmark", label: "Benchmark" },
  { href: "/pricing", label: "Pricing" },
  { href: "/research", label: "Research" },
];

const PLAN_LABELS: Record<string, string> = {
  free: "Free", hunter: "Hunter", apex: "Apex",
  // legacy subscription tiers (pre-credits) — kept so old accounts still render
  founder: "Day Zero", monthly: "Operator", yearly: "Overwatch",
};

export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <Link href="/" className={`group flex items-center gap-2.5 ${className}`} aria-label="HUNTR home">
      <BrandMark lock className="h-8 w-8 transition-transform duration-500 ease-out group-hover:rotate-90" />
      <span className="display text-[1.35rem] tracking-tightest text-grad">HUNTR</span>
      <span className="live-dot ml-0.5 hidden h-1.5 w-1.5 sm:inline-block" title="Operator online" />
    </Link>
  );
}

function GearIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <circle cx="12" cy="12" r="3.2" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 2.8v2.2M12 19v2.2M21.2 12H19M5 12H2.8M18.5 5.5l-1.6 1.6M7.1 16.9l-1.6 1.6M18.5 18.5l-1.6-1.6M7.1 7.1 5.5 5.5"
        stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}
function ChevronIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// Signed-in dropdown: avatar monogram → menu with email/plan, settings, sign out.
function AccountMenu({ user, onSignOut }: { user: Me | null; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const monogram = (user?.email?.[0] ?? "?").toUpperCase();
  const plan = user?.plan ?? "free";

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onKey); };
  }, []);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-full border border-line-2 bg-bg/60 py-1 pl-1 pr-2.5 transition-all duration-200 hover:border-brand hover:shadow-glow-brand"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
      >
        <span className="grid h-7 w-7 place-items-center rounded-full bg-grad-brand text-xs font-bold text-brand-ink">
          {monogram}
        </span>
        <ChevronIcon className={`h-3.5 w-3.5 text-muted transition-transform ${open ? "rotate-180 text-brand" : ""}`} />
      </button>

      {open && (
        <div
          role="menu"
          className="enter absolute right-0 z-[60] mt-2 w-64 overflow-hidden rounded-xl border border-line-2 bg-surface2 shadow-2"
        >
          <div className="border-b border-line px-4 py-3.5">
            <p className="truncate text-sm font-semibold text-fg">{user?.email ?? "Signed in"}</p>
            <span className={`statuspill mt-2 ${plan !== "free" ? "text-green" : "text-faint"}`}>
              <span className="dot" />{PLAN_LABELS[plan] ?? plan}
            </span>
          </div>
          <div className="p-1.5">
            <Link href="/dashboard/" onClick={() => setOpen(false)} role="menuitem"
              className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted transition-colors hover:bg-brand/10 hover:text-fg">
              <span className="grid h-4 w-4 place-items-center"><span className="live-dot" /></span> Hunt dashboard
            </Link>
            <Link href="/account/" onClick={() => setOpen(false)} role="menuitem"
              className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-muted transition-colors hover:bg-brand/10 hover:text-fg">
              <GearIcon className="h-4 w-4" /> Account &amp; settings
            </Link>
            {plan === "free" && (
              <Link href="/pricing/" onClick={() => setOpen(false)} role="menuitem"
                className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-brand transition-colors hover:bg-brand/10">
                <span className="grid h-4 w-4 place-items-center">★</span> Upgrade plan
              </Link>
            )}
          </div>
          <div className="border-t border-line p-1.5">
            <button type="button" onClick={() => { setOpen(false); onSignOut(); }} role="menuitem"
              className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm text-muted transition-colors hover:bg-critical/10 hover:text-critical">
              <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" aria-hidden>
                <path d="M15 12H4m0 0 3.5-3.5M4 12l3.5 3.5M9 7V5a2 2 0 0 1 2-2h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7a2 2 0 0 1-2-2v-2"
                  stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function Nav() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  // auth state (client-only; static export). "?" until we've checked the token.
  const [auth, setAuth] = useState<"?" | "in" | "out">("?");
  const [user, setUser] = useState<Me | null>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!getToken()) { setAuth("out"); return; }
    setAuth("in"); // optimistic — token present
    me()
      .then((u) => { setUser(u); setAuth("in"); })
      .catch((e) => {
        if (e instanceof ApiError && (e.status === 401 || e.status === 404)) {
          clearToken(); setAuth("out");
        }
        // other errors (offline/5xx): keep optimistic "in", just no email
      });
  }, [pathname]);

  const signOut = () => { clearToken(); setAuth("out"); setUser(null); window.location.assign("/"); };

  const isActive = (href: string) => pathname === href || pathname.startsWith(href + "/");

  return (
    <header
      className={`sticky top-0 z-50 transition-colors ${
        scrolled ? "border-b border-line bg-bg/95 shadow-1" : "border-b border-transparent bg-bg/80"
      }`}
      style={{ WebkitBackdropFilter: "none", backdropFilter: "none" }}
    >
      <nav className="site-wrap flex h-16 items-center justify-between">
        <Wordmark />
        <div className="hidden items-center gap-8 md:flex">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={`label ulink ${isActive(l.href) ? "active text-fg" : "text-muted hover:text-fg"}`}
            >
              {l.label}
            </Link>
          ))}
          {/* auth slot — reserve a little space while unknown to avoid a flash */}
          {auth === "?" && <span className="h-9 w-9" aria-hidden />}
          {auth === "out" && (
            <>
              <Link href="/login" className="label ulink text-muted hover:text-fg">Sign in</Link>
              <Link href="/signup" className="btn-brand btn-sm" data-magnetic>Sign up</Link>
            </>
          )}
          {auth === "in" && (
            <>
              <Link href="/dashboard/" className="btn-live btn-sm">
                <span className="live-dot" /> Console
              </Link>
              <AccountMenu user={user} onSignOut={signOut} />
            </>
          )}
        </div>
        <button
          className="flex h-10 w-10 items-center justify-center md:hidden"
          aria-label={open ? "Close menu" : "Open menu"}
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
        >
          <span className="relative block h-4 w-6">
            <span className={`absolute left-0 h-[2px] w-6 bg-fg transition-all ${open ? "top-[7px] rotate-45" : "top-0"}`} />
            <span className={`absolute left-0 top-[7px] h-[2px] w-6 bg-fg transition-all ${open ? "opacity-0" : "opacity-100"}`} />
            <span className={`absolute left-0 h-[2px] w-6 bg-fg transition-all ${open ? "top-[7px] -rotate-45" : "top-[14px]"}`} />
          </span>
        </button>
      </nav>
      {open && (
        <div className="enter border-t border-line bg-bg/95 md:hidden">
          <div className="site-wrap flex flex-col gap-1 py-4">
            {links.map((l) => (
              <Link key={l.href} href={l.href} onClick={() => setOpen(false)} aria-current={isActive(l.href) ? "page" : undefined}
                className={`label flex items-center gap-2.5 py-3 ${isActive(l.href) ? "text-brand" : "text-fg"}`}>
                {isActive(l.href) && <span className="h-1 w-1 rounded-full bg-cyan" aria-hidden />}
                {l.label}
              </Link>
            ))}
            {auth === "in" ? (
              <>
                {user?.email && <p className="label py-3 text-faint">{user.email}</p>}
                <Link href="/dashboard/" onClick={() => setOpen(false)} className="label flex items-center gap-2 py-3 text-green">
                  <span className="live-dot" /> Hunt console
                </Link>
                <Link href="/account/" onClick={() => setOpen(false)} className="label flex items-center gap-2 py-3 text-fg">
                  <GearIcon className="h-4 w-4" /> Account &amp; settings
                </Link>
                <button type="button" onClick={() => { setOpen(false); signOut(); }} className="label py-3 text-left text-critical">
                  Sign out
                </button>
              </>
            ) : (
              <>
                <Link href="/login" onClick={() => setOpen(false)} className="label py-3 text-fg">Sign in</Link>
                <Link href="/signup" onClick={() => setOpen(false)} className="btn-brand mt-2 w-full">Sign up</Link>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
}
