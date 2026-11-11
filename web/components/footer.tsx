import Link from "next/link";
import { SUPPORT_EMAIL } from "@/components/legal";

export function Footer() {
  return (
    <footer className="border-t border-line bg-surface text-fg">
      <div className="site-wrap py-14">
        <div className="flex flex-col gap-10 md:flex-row md:items-end md:justify-between">
          <div>
            <Link href="/" className="display text-4xl tracking-tightest text-fg sm:text-5xl">
              HUNTR<span className="text-brand">.</span>
            </Link>
            <p className="mt-4 max-w-sm text-sm text-muted">
              The autonomous operator for bug bounty. It hunts — you decide.
            </p>
            <p className="mt-4 text-sm text-muted">
              Support:{" "}
              <a href={`mailto:${SUPPORT_EMAIL}`} className="ulink text-fg hover:text-brand">
                {SUPPORT_EMAIL}
              </a>
            </p>
          </div>
          <nav className="flex flex-wrap gap-x-8 gap-y-3">
            {[
              { href: "/", label: "Home" },
              { href: "/platform", label: "Platform" },
              { href: "/benchmark", label: "Benchmark" },
              { href: "/research", label: "Research" },
              { href: "/pricing", label: "Pricing" },
              { href: "/access", label: "Access" },
            ].map((l) => (
              <Link key={l.href} href={l.href} className="label ulink text-muted hover:text-fg">
                {l.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="mt-12 flex flex-col gap-3 border-t border-line pt-6 text-xs text-faint sm:flex-row sm:items-center sm:justify-between">
          <nav className="flex flex-wrap gap-x-6 gap-y-2">
            <Link href="/terms" className="ulink text-faint hover:text-fg">Terms of Service</Link>
            <Link href="/privacy" className="ulink text-faint hover:text-fg">Privacy Policy</Link>
            <Link href="/acceptable-use" className="ulink text-faint hover:text-fg">Acceptable Use</Link>
          </nav>
          <span>© {new Date().getFullYear()} HUNTR · Authorized targets only</span>
        </div>
      </div>
    </footer>
  );
}
