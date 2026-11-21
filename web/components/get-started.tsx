import Link from "next/link";
import { Reveal } from "@/components/reveal";
import { BrandMark } from "@/components/brand-mark";

// Self-serve CTA pair. Primary → /signup (gradient: the signature CTA);
// secondary → /pricing. `onAccent` is kept for back-compat and is a no-op now
// that CTA bands are dark (see <CtaBand>).
export function GetStarted({
  className = "",
  secondary = true,
}: {
  className?: string;
  onAccent?: boolean;
  /** show the "See pricing" secondary link */
  secondary?: boolean;
}) {
  return (
    <div className={`flex flex-wrap items-center gap-4 ${className}`}>
      <Link href="/signup/" className="btn-grad" data-magnetic>
        Start hunting
      </Link>
      {secondary && (
        <Link href="/pricing/" className="btn-outline">
          See pricing
        </Link>
      )}
    </div>
  );
}

/** Closing call-to-action band shared by every marketing page. Dark field, the
 *  reticle mark as the focal point, a purple→green glow (intent → outcome). */
export function CtaBand({ title, body, children }: { title: string; body?: string; children?: React.ReactNode }) {
  return (
    <section className="relative overflow-hidden border-t border-line bg-bg">
      <div className="grad-rule absolute inset-x-0 top-0" aria-hidden />
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(50% 70% at 30% 100%, rgba(139,92,246,0.30), transparent 70%), radial-gradient(45% 65% at 72% 100%, rgba(74,222,128,0.18), transparent 70%)",
        }}
        aria-hidden
      />
      <div className="site-wrap relative py-24 text-center sm:py-32">
        <Reveal type="mask">
          <BrandMark className="mx-auto h-14 w-14" glow />
          <h2 className="display mx-auto mt-8 max-w-[16ch] text-[clamp(2.4rem,6.5vw,5.5rem)] text-fg">{title}</h2>
        </Reveal>
        <Reveal delay={150}>
          {body && <p className="mx-auto mt-6 max-w-[46ch] text-lg leading-relaxed text-fg/70">{body}</p>}
          <div className="mt-10 flex justify-center">{children ?? <GetStarted />}</div>
        </Reveal>
      </div>
    </section>
  );
}
