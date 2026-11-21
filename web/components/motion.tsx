"use client";
import { useEffect } from "react";
import { usePathname } from "next/navigation";
import { gsap } from "gsap";

// Native scroll (no smoothing). Pointer effects only (magnetic buttons + card lantern).
export function Motion() {
  const pathname = usePathname();

  useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;

    const cleanups: Array<() => void> = [];

    document.querySelectorAll<HTMLElement>("[data-magnetic]").forEach((el) => {
      const move = (e: PointerEvent) => {
        const r = el.getBoundingClientRect();
        gsap.to(el, { x: (e.clientX - (r.left + r.width / 2)) * 0.2, y: (e.clientY - (r.top + r.height / 2)) * 0.35, duration: 0.4, ease: "power3.out" });
      };
      const leave = () => gsap.to(el, { x: 0, y: 0, duration: 0.5, ease: "power3.out" });
      el.addEventListener("pointermove", move as EventListener);
      el.addEventListener("pointerleave", leave);
      cleanups.push(() => {
        el.removeEventListener("pointermove", move as EventListener);
        el.removeEventListener("pointerleave", leave);
      });
    });

    document.querySelectorAll<HTMLElement>("[data-lantern]").forEach((el) => {
      const move = (e: PointerEvent) => {
        const r = el.getBoundingClientRect();
        el.style.setProperty("--mx", `${e.clientX - r.left}px`);
        el.style.setProperty("--my", `${e.clientY - r.top}px`);
      };
      el.addEventListener("pointermove", move as EventListener);
      cleanups.push(() => el.removeEventListener("pointermove", move as EventListener));
    });

    return () => cleanups.forEach((fn) => fn());
  }, [pathname]);

  return null;
}
