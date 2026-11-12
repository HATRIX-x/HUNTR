"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import { BrandMark } from "@/components/brand-mark";

const links = [
  { href: "/platform", label: "Platform" },
  { href: "/benchmark", label: "Benchmark" },
  { href: "/pricing", label: "Pricing" },
  { href: "/research", label: "Research" },
];

export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <Link href="/" className={`flex items-center gap-2 ${className}`} aria-label="HUNTR home">
      <BrandMark className="h-8 w-8" />
      <span className="display text-xl tracking-tightest text-fg">HUNTR</span>
    </Link>
  );
}

export function Nav() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const isActive = (href: string) => pathname === href || pathname.startsWith(href + "/");

  return (
    <header
      className={`sticky top-0 z-50 transition-colors ${
        scrolled ? "border-b border-line bg-bg/95" : "border-b border-transparent bg-bg/80"
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
          <Link href="/access" className="btn-brand" data-magnetic>
            Request access
          </Link>
        </div>
        <button
          className="flex h-10 w-10 items-center justify-center md:hidden"
          aria-label="Menu"
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
        <div className="border-t border-line bg-bg md:hidden">
          <div className="site-wrap flex flex-col gap-1 py-4">
            {links.map((l) => (
              <Link key={l.href} href={l.href} onClick={() => setOpen(false)} className="label py-3 text-fg">
                {l.label}
              </Link>
            ))}
            <Link href="/access" onClick={() => setOpen(false)} className="btn-brand mt-2 w-full">
              Request access
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
