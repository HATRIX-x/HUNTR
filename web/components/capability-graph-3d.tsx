"use client";
import { useEffect, useRef } from "react";
import type { GraphNode, GraphEdge } from "@/lib/api";

/** Interactive 3D capability graph for the console Map view. Real nodes/edges
 *  from the hunt, laid out on a Fibonacci sphere, projected with depth, and
 *  orbitable by drag. Hover highlights a node + its neighbours. Pure canvas —
 *  no 3D lib. Respects reduced-motion (auto-rotate off, still draggable). */

const TYPE_COL: Record<string, number[]> = {
  root: [167, 139, 250], host: [167, 139, 250], target: [167, 139, 250], domain: [167, 139, 250],
  endpoint: [74, 222, 128], route: [74, 222, 128], url: [74, 222, 128],
  finding: [255, 93, 108], vuln: [255, 93, 108],
  param: [231, 184, 75], parameter: [231, 184, 75],
};
const MUTED = [138, 144, 156];
const colFor = (t?: string) => TYPE_COL[(t || "").toLowerCase()] ?? MUTED;

type P = { x: number; y: number; z: number; r: number; type?: string; label?: string };

export function CapabilityGraph3D({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const wrap = useRef<HTMLDivElement | null>(null);
  const canvas = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const cv = canvas.current, box = wrap.current;
    if (!cv || !box || !nodes.length) return;
    const ctx = cv.getContext("2d")!;
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // degree (for node size + hub pull)
    const idx: Record<string, number> = {};
    nodes.forEach((n, i) => (idx[n.id] = i));
    const deg = new Array(nodes.length).fill(0);
    const E: [number, number][] = [];
    for (const e of edges) {
      const a = idx[e.source], b = idx[e.target];
      if (a === undefined || b === undefined || a === b) continue;
      E.push([a, b]); deg[a]++; deg[b]++;
    }
    const maxDeg = Math.max(1, ...deg);

    // Fibonacci-sphere layout; higher-degree nodes pulled slightly inward (hubs core)
    const gold = Math.PI * (3 - Math.sqrt(5));
    const N = nodes.length;
    const pts: P[] = nodes.map((n, i) => {
      const y = N > 1 ? 1 - (i / (N - 1)) * 2 : 0;
      const rr = Math.sqrt(Math.max(0, 1 - y * y));
      const th = gold * i;
      const shell = 0.55 + 0.45 * (1 - deg[i] / maxDeg);   // hubs → inner shell
      const base = colFor(n.type);
      const isHub = base === TYPE_COL.root;
      return {
        x: Math.cos(th) * rr * shell,
        y: y * shell,
        z: Math.sin(th) * rr * shell,
        r: Math.max(2.2, (isHub ? 4.2 : 2.8) + (deg[i] / maxDeg) * 4.5),
        type: n.type,
        label: n.label || n.id,
      };
    });
    const stars = Array.from({ length: 80 }, () => ({
      x: Math.random(), y: Math.random(), r: Math.random() * 1.1 + 0.3, ph: Math.random() * 6.28,
      sp: 0.5 + Math.random(), depth: 0.3 + Math.random() * 0.7,
    }));
    const pulses: { e: number; t: number; spd: number }[] = [];

    let rx = -0.2, ry = 0, vel = 0.0016, dragging = false, lx = 0, ly = 0;
    let W = 0, H = 0, RAD = 0, raf = 0, hover = -1, pointer = { x: -1, y: -1 };
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

    const proj = (n: P) => {
      const cy = Math.cos(ry), sy = Math.sin(ry), cx = Math.cos(rx), sx = Math.sin(rx);
      let x = n.x * cy - n.z * sy, z = n.x * sy + n.z * cy;
      const y = n.y * cx - z * sx; z = n.y * sx + z * cx;
      const focal = 3.0, scale = focal / Math.max(0.6, focal + z);
      return { X: W / 2 + x * scale * RAD, Y: H / 2 + y * scale * RAD, scale, z };
    };
    const rgba = (c: number[], a: number) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

    const frame = (t: number) => {
      const el = t - t0;
      if (!dragging && !reduce) { ry += vel; vel += (0.0016 - vel) * 0.02; }
      ctx.clearRect(0, 0, W, H);

      const px = Math.sin(ry) * 12, py = Math.sin(rx) * 9;
      for (const s of stars) {
        const a = (0.08 + 0.08 * Math.sin(el / 900 * s.sp + s.ph)) * s.depth;
        ctx.fillStyle = `rgba(188,180,220,${a})`;
        ctx.beginPath(); ctx.arc(s.x * W + px * s.depth, s.y * H + py * s.depth, s.r, 0, 7); ctx.fill();
      }

      const PR = pts.map(proj);
      const nbr = new Set<number>();
      if (hover >= 0) { nbr.add(hover); for (const [a, b] of E) { if (a === hover) nbr.add(b); if (b === hover) nbr.add(a); } }

      // edges
      for (const [a, b] of E) {
        const dim = hover >= 0 && !(nbr.has(a) && nbr.has(b));
        const depth = (PR[a].scale + PR[b].scale) / 2;
        const lit = hover >= 0 && nbr.has(a) && nbr.has(b);
        ctx.strokeStyle = lit ? rgba(TYPE_COL.endpoint, 0.5 * depth) : rgba([150, 140, 190], (dim ? 0.05 : 0.16) * depth);
        ctx.lineWidth = (lit ? 1.1 : 0.6) * depth;
        ctx.beginPath(); ctx.moveTo(PR[a].X, PR[a].Y); ctx.lineTo(PR[b].X, PR[b].Y); ctx.stroke();
      }

      // occasional data pulse along a random edge
      if (!reduce && E.length && Math.random() < 0.06) pulses.push({ e: (Math.random() * E.length) | 0, t: 0, spd: 0.015 + Math.random() * 0.02 });
      for (let i = pulses.length - 1; i >= 0; i--) {
        const pu = pulses[i]; pu.t += pu.spd;
        if (pu.t >= 1) { pulses.splice(i, 1); continue; }
        const [a, b] = E[pu.e];
        const X = PR[a].X + (PR[b].X - PR[a].X) * pu.t, Y = PR[a].Y + (PR[b].Y - PR[a].Y) * pu.t;
        ctx.beginPath(); ctx.fillStyle = rgba(TYPE_COL.endpoint, 0.9); ctx.shadowColor = rgba(TYPE_COL.endpoint, 0.9); ctx.shadowBlur = 8;
        ctx.arc(X, Y, 1.7, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
      }

      // nodes back-to-front
      const order = pts.map((_, i) => i).sort((i, j) => PR[j].z - PR[i].z);
      for (const i of order) {
        const n = pts[i], p = PR[i], col = colFor(n.type);
        const depth = 0.4 + p.scale * 0.6;
        const dim = hover >= 0 && !nbr.has(i);
        const alpha = (dim ? 0.22 : 1) * depth;
        const r = Math.max(0.4, n.r * p.scale);
        if (hover === i || col !== MUTED) { ctx.shadowColor = rgba(col, 0.8 * alpha); ctx.shadowBlur = (hover === i ? 16 : 9) * p.scale; }
        ctx.beginPath(); ctx.fillStyle = rgba(col, alpha); ctx.arc(p.X, p.Y, r, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
        const showLabel = n.label && (nbr.has(i) || (hover < 0 && p.scale > 1.02 && n.r > 5));
        if (showLabel) {
          ctx.font = "10px ui-monospace, monospace";
          ctx.fillStyle = rgba([236, 238, 242], 0.82 * (dim ? 0.3 : 1));
          ctx.fillText(n.label!.slice(0, 26), p.X + r + 5, p.Y + 3);
        }
      }

      if (pointer.x >= 0) {
        let best = -1, bd = 20 * 20;
        for (const i of order) { const p = PR[i]; const d = (p.X - pointer.x) ** 2 + (p.Y - pointer.y) ** 2; if (d < bd) { bd = d; best = i; } }
        hover = best;
      } else hover = -1;

      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    const down = (e: PointerEvent) => { dragging = true; lx = e.clientX; ly = e.clientY; cv.setPointerCapture(e.pointerId); };
    const move = (e: PointerEvent) => {
      const rct = cv.getBoundingClientRect(); pointer = { x: e.clientX - rct.left, y: e.clientY - rct.top };
      if (!dragging) return;
      ry += (e.clientX - lx) * 0.006; rx += (e.clientY - ly) * 0.006; rx = Math.max(-1.2, Math.min(1.2, rx));
      vel = (e.clientX - lx) * 0.006; lx = e.clientX; ly = e.clientY;
    };
    const up = () => { dragging = false; };
    const out = () => { pointer = { x: -1, y: -1 }; };
    cv.addEventListener("pointerdown", down); window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up); cv.addEventListener("pointerleave", out);

    return () => {
      cancelAnimationFrame(raf); ro.disconnect();
      cv.removeEventListener("pointerdown", down); window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up); cv.removeEventListener("pointerleave", out);
    };
  }, [nodes, edges]);

  return (
    <div ref={wrap} className="relative h-[62vh] w-full select-none">
      <canvas ref={canvas} data-hot className="h-full w-full touch-none" style={{ cursor: "grab" }} />
      <div className="hud pointer-events-none absolute bottom-3 right-4 text-[10px] uppercase tracking-[0.12em] text-faint">drag to orbit · hover a node</div>
    </div>
  );
}
