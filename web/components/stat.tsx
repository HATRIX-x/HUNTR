"use client";
import { useEffect, useRef, useState } from "react";

export function Stat({
  value,
  suffix = "",
  label,
  sub,
  tone = "brand",
}: {
  value: number;
  suffix?: string;
  label: string;
  sub?: string;
  tone?: "brand" | "green" | "fg";
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  // Initialise to the real value so the static HTML (and no-JS / crawlers) always
  // shows the correct figure. The count-up is a progressive enhancement only.
  const [n, setN] = useState(value);
  const ran = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el || value === 0) return;
    const reduce =
      typeof window !== "undefined" &&
      window.matchMedia &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce || typeof IntersectionObserver === "undefined") return; // keep the real value

    const animate = () => {
      if (ran.current) return;
      ran.current = true;
      const dur = 1200;
      const t0 = performance.now();
      const step = (t: number) => {
        const p = Math.min(1, (t - t0) / dur);
        const e = 1 - Math.pow(1 - p, 3);
        setN(Math.round(value * e));
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    };

    // If the stat is already on screen at load, leave the real number in place
    // (no flash from value -> 0 -> value). Only animate when it scrolls in from below.
    const rect = el.getBoundingClientRect();
    const alreadyVisible = rect.top < window.innerHeight && rect.bottom > 0;
    if (alreadyVisible) return;

    setN(0);
    const io = new IntersectionObserver(
      (es) => es.forEach((e) => e.isIntersecting && animate()),
      { threshold: 0.4 }
    );
    io.observe(el);
    return () => io.disconnect();
  }, [value]);

  const color = tone === "green" ? "text-green" : tone === "fg" ? "text-fg" : "text-brand";

  return (
    <div ref={ref}>
      <div className={`numeral text-6xl sm:text-7xl lg:text-8xl ${tone === "fg" ? "text-fg" : color}`}>
        {n}
        {suffix && <span className={color}>{suffix}</span>}
      </div>
      <div className="mt-4 label text-fg">{label}</div>
      {sub && <p className="mt-2 max-w-[28ch] text-sm leading-relaxed text-muted">{sub}</p>}
    </div>
  );
}
