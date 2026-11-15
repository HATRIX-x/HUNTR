"use client";
import { useEffect, useRef } from "react";
import { usePathname } from "next/navigation";

// App surfaces are working tools — they keep the native cursor for precise
// clicking in nav, tables and forms. The reticle is a marketing-page flourish.
const APP_ROUTES = ["/dashboard", "/account", "/login", "/signup"];

/** A targeting-reticle cursor for the marketing pages. Follows the pointer, grows
 *  over interactive elements. Desktop/hover only — hidden on touch, and off on the
 *  operator console (native cursor there). */
export function ReticleCursor() {
  const ref = useRef<HTMLDivElement | null>(null);
  const pathname = usePathname();

  useEffect(() => {
    if (APP_ROUTES.some((r) => pathname === r || pathname.startsWith(r + "/"))) return;
    if (window.matchMedia && window.matchMedia("(hover: none)").matches) return;
    const el = ref.current;
    if (!el) return;
    document.body.classList.add("reticle-on"); // hides native cursor via CSS; removed on unmount
    let x = window.innerWidth / 2, y = window.innerHeight / 2, tx = x, ty = y, raf = 0;
    const loop = () => {
      x += (tx - x) * 0.25; y += (ty - y) * 0.25;
      el.style.setProperty("--rx", `${x}px`);
      el.style.setProperty("--ry", `${y}px`);
      raf = requestAnimationFrame(loop);
    };
    const move = (e: PointerEvent) => {
      tx = e.clientX; ty = e.clientY;
      el.classList.add("tracking"); // stays hidden until the pointer actually moves
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
      document.body.classList.remove("reticle-on");
      el.classList.remove("tracking");
      window.removeEventListener("pointermove", move);
      document.removeEventListener("pointerleave", leave);
      document.removeEventListener("pointerenter", enter);
    };
  }, [pathname]);

  // No reticle element at all on the app surfaces (keeps the native cursor clean).
  if (APP_ROUTES.some((r) => pathname === r || pathname.startsWith(r + "/"))) return null;

  return (
    <div ref={ref} className="reticle" aria-hidden="true">
      <i /><i /><i /><i /><b />
    </div>
  );
}
