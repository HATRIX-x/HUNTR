"use client";
import { useEffect, useRef } from "react";

/** A targeting-reticle cursor for the operator console. Follows the pointer, grows
 *  over interactive elements. Desktop/hover only — hidden on touch. */
export function ReticleCursor() {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (window.matchMedia && window.matchMedia("(hover: none)").matches) return;
    const el = ref.current;
    if (!el) return;
    let x = window.innerWidth / 2, y = window.innerHeight / 2, tx = x, ty = y, raf = 0;
    const loop = () => {
      x += (tx - x) * 0.25; y += (ty - y) * 0.25;
      el.style.setProperty("--rx", `${x}px`);
      el.style.setProperty("--ry", `${y}px`);
      raf = requestAnimationFrame(loop);
    };
    const move = (e: PointerEvent) => {
      tx = e.clientX; ty = e.clientY;
      const t = e.target as HTMLElement;
      const hot = !!t.closest("a,button,input,[data-hot]");
      el.classList.toggle("hot", hot);
    };
    const leave = () => (el.style.opacity = "0");
    const enter = () => (el.style.opacity = "1");
    window.addEventListener("pointermove", move);
    document.addEventListener("pointerleave", leave);
    document.addEventListener("pointerenter", enter);
    raf = requestAnimationFrame(loop);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", move);
      document.removeEventListener("pointerleave", leave);
      document.removeEventListener("pointerenter", enter);
    };
  }, []);

  return (
    <div ref={ref} className="reticle" aria-hidden="true">
      <i /><i /><i /><i /><b />
    </div>
  );
}
