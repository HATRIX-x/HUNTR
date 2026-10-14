import Link from "next/link";
import type { ReactNode } from "react";
import { Reveal } from "@/components/reveal";
import { Waitlist } from "@/components/waitlist";

/** Prose typography for long-form research articles, styled with Tailwind
 *  arbitrary variants so no @tailwindcss/typography plugin is needed. */
const prose = [
  "max-w-[68ch] text-[1.05rem] leading-relaxed text-fg/80",
  "[&>p]:mt-6",
  "[&>h2]:display [&>h2]:mt-16 [&>h2]:mb-5 [&>h2]:text-[clamp(1.6rem,3.6vw,2.4rem)] [&>h2]:leading-[1.08] [&>h2]:text-fg",
  "[&>h3]:display [&>h3]:mt-10 [&>h3]:mb-3 [&>h3]:text-xl [&>h3]:text-fg",
  "[&>ul]:mt-6 [&>ul]:space-y-3 [&>ul]:pl-5 [&>ul]:list-disc [&>ul]:marker:text-brand",
  "[&>ol]:mt-6 [&>ol]:space-y-3 [&>ol]:pl-5 [&>ol]:list-decimal [&>ol]:marker:text-brand",
  "[&_li]:pl-2",
  "[&_a]:text-brand [&_a]:underline [&_a]:underline-offset-4 [&_a:hover]:text-fg",
  "[&_strong]:font-semibold [&_strong]:text-fg",
  "[&_code]:rounded [&_code]:bg-surface2 [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:text-[0.9em] [&_code]:text-brand",
  "[&>blockquote]:mt-8 [&>blockquote]:border-l-4 [&>blockquote]:border-brand [&>blockquote]:bg-surface [&>blockquote]:p-6 [&>blockquote]:text-fg/75",
].join(" ");

export function ArticleShell({
  eyebrow,
  title,
  dek,
  readMins,
  updated,
  children,
}: {
  eyebrow: string;
  title: ReactNode;
  dek: string;
  readMins: number;
  updated: string;
  children: ReactNode;
}) {
  return (
    <main>
      {/* HERO */}
      <section className="border-b border-line">
        <div className="site-wrap pb-14 pt-14 sm:pb-16 sm:pt-20">
          <nav className="label flex items-center gap-2 text-muted" aria-label="Breadcrumb">
            <Link href="/research" className="ulink hover:text-fg">
              Research
            </Link>
            <span className="text-faint">/</span>
            <span className="text-faint">{eyebrow}</span>
          </nav>
          <h1 className="display mt-7 max-w-[20ch] text-[clamp(2.2rem,6vw,4.6rem)] leading-[1.02]" data-reveal="up">
            {title}
          </h1>
          <Reveal as="p" delay={120} className="mt-7 max-w-[58ch] text-lg leading-relaxed text-fg/75">
            {dek}
          </Reveal>
          <Reveal delay={200} className="mt-8 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
            <span className="label text-faint">{readMins} min read</span>
            <span className="h-1 w-1 rounded-full bg-faint" />
            <span className="label text-faint">Updated {updated}</span>
            <span className="h-1 w-1 rounded-full bg-faint" />
            <span className="label text-muted">By HUNTR</span>
          </Reveal>
        </div>
      </section>

      {/* BODY */}
      <section className="border-b border-line">
        <div className="site-wrap py-16 sm:py-20">
          <article className={prose}>{children}</article>
        </div>
      </section>

      {/* CTA */}
      <section className="bg-brand text-brand-ink">
        <div className="site-wrap py-24 text-center sm:py-28">
          <Reveal type="mask">
            <span className="label text-brand-ink/70">Early access</span>
            <h2 className="display mx-auto mt-6 max-w-[18ch] text-[clamp(2.2rem,6vw,5rem)] text-brand-ink">
              See it on a target you own.
            </h2>
          </Reveal>
          <Reveal delay={150} className="mx-auto mt-10 flex max-w-md justify-center">
            <Waitlist onAccent className="w-full" />
          </Reveal>
        </div>
      </section>
    </main>
  );
}
