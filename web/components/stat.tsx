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
  const [n, setN] = useState(0);
  const ran = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const run = () => {
      if (ran.current) return;
      ran.current = true;
      if (value === 0) {
        setN(0);
        return;
      }
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
    if (typeof IntersectionObserver === "undefined") {
      setN(value);
      return;
    }
    const io = new IntersectionObserver((es) => es.forEach((e) => e.isIntersecting && run()), { threshold: 0.4 });
    io.observe(el);
    const t = setTimeout(run, 2600);
    return () => {
      io.disconnect();
      clearTimeout(t);
    };
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
