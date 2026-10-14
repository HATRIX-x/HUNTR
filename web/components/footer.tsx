import Link from "next/link";

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
          </div>
          <nav className="flex flex-wrap gap-x-8 gap-y-3">
            {[
              { href: "/", label: "Home" },
              { href: "/platform", label: "Platform" },
              { href: "/benchmark", label: "Benchmark" },
              { href: "/research", label: "Research" },
              { href: "/access", label: "Access" },
            ].map((l) => (
              <Link key={l.href} href={l.href} className="label ulink text-muted hover:text-fg">
                {l.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="mt-12 flex flex-col gap-2 border-t border-line pt-6 text-xs text-faint sm:flex-row sm:items-center sm:justify-between">
          <span className="label text-faint">It hunts. You decide.</span>
          <span>© {new Date().getFullYear()} HUNTR · Authorized targets only</span>
        </div>
      </div>
    </footer>
  );
}
