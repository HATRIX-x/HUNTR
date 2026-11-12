"use client";
import { useEffect, useRef } from "react";

type Node = { x: number; y: number; z: number; kind: "root" | "ep" | "crit" | "high"; label?: string; found: number };

const LABELS = ["/api", "SQLi", "/auth", "IDOR", "SSRF", "/admin", "graphql", "/upload", "XSS", "/token"];
const COL = {
  root: "#A78BFA", ep: "#4ADE80", crit: "#ff5d6c", high: "#e7b84b",
  faint: "rgba(138,144,156,0.5)", edge: "rgba(167,139,250,0.14)", edgeHot: "rgba(74,222,128,0.4)",
};

export function SurfaceGraph3D() {
  const wrap = useRef<HTMLDivElement | null>(null);
  const canvas = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const cv = canvas.current, box = wrap.current;
    if (!cv || !box) return;
    const ctx = cv.getContext("2d")!;
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // ── build nodes on a fibonacci sphere ──
    const N = 46;
    const nodes: Node[] = [{ x: 0, y: 0, z: 0, kind: "root", label: "target", found: 0 }];
    const gold = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < N; i++) {
      const y = 1 - (i / (N - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const th = gold * i;
      const kind: Node["kind"] = i % 17 === 3 ? "crit" : i % 11 === 5 ? "high" : "ep";
      nodes.push({ x: Math.cos(th) * r, y, z: Math.sin(th) * r, kind, label: i % 5 === 0 ? LABELS[(i / 5) % LABELS.length | 0] : undefined, found: 400 + i * 95 });
    }
    // edges: each node to root sometimes + nearest neighbours
    const edges: [number, number][] = [];
    for (let i = 1; i < nodes.length; i++) {
      if (i % 3 === 0) edges.push([0, i]);
      let best = -1, bd = 1e9;
      for (let j = 1; j < nodes.length; j++) {
        if (j === i) continue;
        const d = (nodes[i].x - nodes[j].x) ** 2 + (nodes[i].y - nodes[j].y) ** 2 + (nodes[i].z - nodes[j].z) ** 2;
        if (d < bd) { bd = d; best = j; }
      }
      if (best > 0) edges.push([i, best]);
    }

    let rx = -0.3, ry = 0, auto = 0.0024, dragging = false, lx = 0, ly = 0, vel = 0.0024;
    let W = 0, H = 0, RAD = 0, raf = 0;
    const t0 = performance.now();

    const size = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = box.clientWidth; H = box.clientHeight;
      cv.width = W * dpr; cv.height = H * dpr; cv.style.width = W + "px"; cv.style.height = H + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      RAD = Math.min(W, H) * 0.42;
    };
    size();
    const ro = new ResizeObserver(size); ro.observe(box);

    const proj = (n: Node) => {
      // rotate Y then X
      const cy = Math.cos(ry), sy = Math.sin(ry), cx = Math.cos(rx), sx = Math.sin(rx);
      let x = n.x * cy - n.z * sy;
      let z = n.x * sy + n.z * cy;
      let y = n.y * cx - z * sx;
      z = n.y * sx + z * cx;
      const focal = 3.2, scale = focal / (focal + z);
      return { sx2: W / 2 + x * scale * RAD, sy2: H / 2 + y * scale * RAD, scale, z };
    };

    const frame = (t: number) => {
      const el = t - t0;
      if (!dragging) ry += vel; else vel = vel * 0.9;
      if (!dragging && !reduce) ry += 0; // auto handled by vel
      ctx.clearRect(0, 0, W, H);
      const P = nodes.map(proj);
      // edges
      for (const [a, b] of edges) {
        const fa = el > nodes[a].found, fb = el > nodes[b].found;
        ctx.strokeStyle = fa && fb ? COL.edgeHot : COL.edge;
        ctx.lineWidth = fa && fb ? 1.1 : 0.7;
        ctx.beginPath(); ctx.moveTo(P[a].sx2, P[a].sy2); ctx.lineTo(P[b].sx2, P[b].sy2); ctx.stroke();
      }
      // nodes back-to-front
      const order = nodes.map((_, i) => i).sort((i, j) => P[j].z - P[i].z);
      for (const i of order) {
        const n = nodes[i], p = P[i];
        const found = el > n.found || n.kind === "root";
        const base = n.kind === "root" ? COL.root : !found ? COL.faint : n.kind === "crit" ? COL.crit : n.kind === "high" ? COL.high : COL.ep;
        const r = (n.kind === "root" ? 5.5 : 3.1) * p.scale;
        if (found && n.kind !== "root") { // glow
          ctx.globalAlpha = 0.16; ctx.fillStyle = base;
          ctx.beginPath(); ctx.arc(p.sx2, p.sy2, r * 3, 0, 7); ctx.fill();
          ctx.globalAlpha = 1;
        }
        ctx.beginPath(); ctx.fillStyle = base; ctx.arc(p.sx2, p.sy2, r, 0, 7); ctx.fill();
        if (n.kind === "root") { ctx.strokeStyle = COL.root; ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(p.sx2, p.sy2, r + 6 * p.scale, 0, 7); ctx.globalAlpha = 0.5; ctx.stroke(); ctx.globalAlpha = 1; }
        if (n.label && found && p.scale > 0.82) {
          ctx.font = "10px ui-monospace, monospace"; ctx.fillStyle = "rgba(236,238,242,0.7)";
          ctx.fillText(n.label, p.sx2 + r + 4, p.sy2 + 3);
        }
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    // drag to orbit
    const down = (e: PointerEvent) => { dragging = true; lx = e.clientX; ly = e.clientY; cv.setPointerCapture(e.pointerId); };
    const move = (e: PointerEvent) => { if (!dragging) return; ry += (e.clientX - lx) * 0.006; rx += (e.clientY - ly) * 0.006; rx = Math.max(-1.2, Math.min(1.2, rx)); vel = (e.clientX - lx) * 0.006; lx = e.clientX; ly = e.clientY; };
    const up = () => { dragging = false; if (Math.abs(vel) < 0.0008) vel = 0.0024; };
    cv.addEventListener("pointerdown", down); window.addEventListener("pointermove", move); window.addEventListener("pointerup", up);

    return () => { cancelAnimationFrame(raf); ro.disconnect(); cv.removeEventListener("pointerdown", down); window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
  }, []);

  return (
    <div ref={wrap} className="relative aspect-square w-full select-none">
      <canvas ref={canvas} data-hot className="h-full w-full touch-none" style={{ cursor: "grab" }} />
      <div className="hud pointer-events-none absolute left-4 top-4 text-[10px] uppercase tracking-[0.14em] text-faint">
        surface map · <span style={{ color: "var(--validated)" }}>live</span>
      </div>
      <div className="hud pointer-events-none absolute bottom-4 right-4 text-[10px] uppercase tracking-[0.12em] text-faint">drag to orbit</div>
    </div>
  );
}
