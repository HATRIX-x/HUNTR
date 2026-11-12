"use client";
import { useEffect, useRef } from "react";

type Kind = "root" | "ep" | "crit" | "high";
type Node = { x: number; y: number; z: number; kind: Kind; label?: string; order: number; hub: number; foundAt: number };
type Pulse = { e: number; t: number; spd: number };

const LABELS = ["/api", "SQLi", "/auth", "IDOR", "SSRF", "/admin", "graphql", "/upload", "XSS", "/token", "/v2", "JWT"];
const C = {
  root: [167, 139, 250], ep: [74, 222, 128], crit: [255, 93, 108], high: [231, 184, 75],
};

export function SurfaceGraph3D() {
  const wrap = useRef<HTMLDivElement | null>(null);
  const canvas = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const cv = canvas.current, box = wrap.current;
    if (!cv || !box) return;
    const ctx = cv.getContext("2d")!;
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // ── starfield backdrop (parallax + twinkle) ──
    const stars = Array.from({ length: 95 }, () => ({
      x: Math.random(), y: Math.random(), r: Math.random() * 1.1 + 0.3,
      ph: Math.random() * 6.28, sp: 0.5 + Math.random(), depth: 0.3 + Math.random() * 0.7,
    }));

    // ── clustered layout: root → hubs → satellites ──
    const HUBS = 7;
    const nodes: Node[] = [{ x: 0, y: 0, z: 0, kind: "root", label: "target", order: 0, hub: -1, foundAt: 0 }];
    const gold = Math.PI * (3 - Math.sqrt(5));
    const hubIdx: number[] = [];
    for (let h = 0; h < HUBS; h++) {
      const y = 1 - (h / (HUBS - 1)) * 2 * 0.8;
      const r = Math.sqrt(Math.max(0, 1 - y * y));
      const th = gold * h * 2.2;
      hubIdx.push(nodes.length);
      nodes.push({ x: Math.cos(th) * r * 0.55, y: y * 0.55, z: Math.sin(th) * r * 0.55, kind: "ep", label: LABELS[h], order: (h + 1) / (HUBS + 1) * 0.5, hub: -1, foundAt: 0 });
    }
    let li = HUBS;
    for (let h = 0; h < HUBS; h++) {
      const hub = nodes[hubIdx[h]];
      const sats = 7 + (h % 3);
      for (let s = 0; s < sats; s++) {
        const a = (s / sats) * Math.PI * 2 + h, sp = 0.42;
        const nx = hub.x + Math.cos(a) * sp, ny = hub.y + Math.sin(a) * sp * 0.8, nz = hub.z + Math.sin(a * 1.3) * sp;
        const mag = Math.hypot(nx, ny, nz) || 1;
        const kind: Kind = (h * 7 + s) % 19 === 1 ? "crit" : (h * 5 + s) % 9 === 2 ? "high" : "ep";
        nodes.push({ x: nx / mag, y: ny / mag, z: nz / mag, kind, label: s % 4 === 0 ? LABELS[(li) % LABELS.length] : undefined, order: 0.4 + Math.random() * 0.55, hub: hubIdx[h], foundAt: 0 });
        li++;
      }
    }
    // edges
    const edges: [number, number][] = [];
    for (const hi of hubIdx) edges.push([0, hi]);
    nodes.forEach((n, i) => { if (n.hub >= 0) edges.push([n.hub, i]); });
    // a few cross-chain links
    for (let k = 0; k < 7; k++) edges.push([hubIdx[k % HUBS], hubIdx[(k + 2) % HUBS]]);

    const pulses: Pulse[] = [];

    let rx = -0.25, ry = 0, vel = 0.0022, dragging = false, lx = 0, ly = 0;
    let W = 0, H = 0, RAD = 0, raf = 0, hover = -1, pointer = { x: -1, y: -1 };
    const t0 = performance.now();
    const CYCLE = 7000;

    const size = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = box.clientWidth; H = box.clientHeight;
      cv.width = W * dpr; cv.height = H * dpr; cv.style.width = W + "px"; cv.style.height = H + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      RAD = Math.min(W, H) * 0.4;
    };
    size();
    const ro = new ResizeObserver(size); ro.observe(box);

    const proj = (n: Node) => {
      const cy = Math.cos(ry), sy = Math.sin(ry), cx = Math.cos(rx), sx = Math.sin(rx);
      let x = n.x * cy - n.z * sy, z = n.x * sy + n.z * cy;
      let y = n.y * cx - z * sx; z = n.y * sx + z * cx;
      const focal = 3.0, scale = focal / Math.max(0.6, focal + z);
      return { X: W / 2 + x * scale * RAD, Y: H / 2 + y * scale * RAD, scale, z };
    };
    const rgba = (c: number[], a: number) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
    const kcol = (k: Kind) => k === "root" ? C.root : k === "crit" ? C.crit : k === "high" ? C.high : C.ep;

    const frame = (t: number) => {
      const el = t - t0;
      const scanT = reduce ? 1 : (el % CYCLE) / CYCLE;           // sweep 0→1 looping
      const cyc = Math.floor(el / CYCLE);
      if (!dragging) { ry += vel; vel += (0.0022 - vel) * 0.02; }

      ctx.clearRect(0, 0, W, H);

      // starfield — subtle parallax with rotation + twinkle
      const px = Math.sin(ry) * 14, py = Math.sin(rx) * 10;
      for (const s of stars) {
        const a = (0.1 + 0.09 * Math.sin(el / 900 * s.sp + s.ph)) * s.depth;
        ctx.fillStyle = `rgba(188,180,220,${a})`;
        ctx.beginPath();
        ctx.arc(s.x * W + px * s.depth, s.y * H + py * s.depth, s.r, 0, 7);
        ctx.fill();
      }

      const P = nodes.map(proj);
      // neighbours of hovered
      const nbr = new Set<number>();
      if (hover >= 0) { nbr.add(hover); for (const [a, b] of edges) { if (a === hover) nbr.add(b); if (b === hover) nbr.add(a); } }

      // discovery + pulse spawning
      nodes.forEach((n, i) => {
        const found = n.kind === "root" || scanT > n.order;
        if (found && n.foundAt === 0) { n.foundAt = el; }
        if (!found && n.foundAt !== 0 && scanT < 0.05) n.foundAt = 0; // reset on new cycle
      });
      if (!reduce && Math.random() < 0.08) {
        const e = (Math.random() * edges.length) | 0;
        pulses.push({ e, t: 0, spd: 0.012 + Math.random() * 0.02 });
      }

      // ── edges ──
      for (const [a, b] of edges) {
        const fa = nodes[a].foundAt > 0, fb = nodes[b].foundAt > 0;
        const dim = hover >= 0 && !(nbr.has(a) && nbr.has(b));
        const depth = (P[a].scale + P[b].scale) / 2;
        const on = fa && fb;
        ctx.strokeStyle = on ? rgba(C.ep, (dim ? 0.06 : 0.28) * depth) : rgba([120, 110, 160], (dim ? 0.03 : 0.1) * depth);
        ctx.lineWidth = (on ? 1.1 : 0.6) * depth;
        ctx.beginPath(); ctx.moveTo(P[a].X, P[a].Y); ctx.lineTo(P[b].X, P[b].Y); ctx.stroke();
      }

      // ── data pulses along edges ──
      for (let i = pulses.length - 1; i >= 0; i--) {
        const pu = pulses[i]; pu.t += pu.spd;
        if (pu.t >= 1) { pulses.splice(i, 1); continue; }
        const [a, b] = edges[pu.e];
        if (nodes[a].foundAt === 0 || nodes[b].foundAt === 0) { pulses.splice(i, 1); continue; }
        const X = P[a].X + (P[b].X - P[a].X) * pu.t, Y = P[a].Y + (P[b].Y - P[a].Y) * pu.t;
        ctx.beginPath(); ctx.fillStyle = rgba(C.ep, 0.9); ctx.shadowColor = rgba(C.ep, 0.9); ctx.shadowBlur = 8;
        ctx.arc(X, Y, 1.8, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
      }

      // ── scan wavefront ring ──
      if (!reduce) {
        ctx.beginPath(); ctx.strokeStyle = rgba(C.root, 0.12 * (1 - scanT));
        ctx.lineWidth = 1; ctx.arc(W / 2, H / 2, scanT * RAD * 1.5, 0, 7); ctx.stroke();
      }

      // ── nodes, back to front ──
      const order = nodes.map((_, i) => i).sort((i, j) => P[j].z - P[i].z);
      for (const i of order) {
        const n = nodes[i], p = P[i];
        const found = n.foundAt > 0;
        const col = found || n.kind === "root" ? kcol(n.kind) : [120, 126, 140];
        const depth = 0.35 + p.scale * 0.65;                        // depth fog
        const dim = hover >= 0 && !nbr.has(i);
        const alpha = (dim ? 0.25 : 1) * depth;
        const pulse = found ? Math.max(0, 1 - (el - n.foundAt) / 500) : 0; // pop on discover
        const r = Math.max(0.3, (n.kind === "root" ? 5.5 : n.kind === "crit" || n.kind === "high" ? 3.6 : 2.9) * p.scale * (1 + pulse * 0.8));

        if ((found && n.kind !== "ep") || n.kind === "root" || hover === i) {
          ctx.shadowColor = rgba(col, 0.9 * alpha); ctx.shadowBlur = (n.kind === "root" ? 18 : 12) * p.scale;
        }
        ctx.beginPath(); ctx.fillStyle = rgba(col, alpha); ctx.arc(p.X, p.Y, r, 0, 7); ctx.fill();
        ctx.shadowBlur = 0;

        if (n.kind === "root") {
          ctx.strokeStyle = rgba(C.root, 0.5 * alpha); ctx.lineWidth = 1.2;
          ctx.beginPath(); ctx.arc(p.X, p.Y, r + 7 * p.scale, 0, 7); ctx.stroke();
        }
        // labels: only hovered+neighbours, or crit/high facing front
        const showLabel = n.label && (nbr.has(i) || (hover < 0 && (n.kind === "crit" || n.kind === "high" || n.kind === "root") && p.scale > 0.92));
        if (showLabel) {
          ctx.font = "10px ui-monospace, monospace"; ctx.fillStyle = rgba([236, 238, 242], 0.8 * (dim ? 0.3 : 1));
          ctx.fillText(n.label!, p.X + r + 5, p.Y + 3);
        }
      }

      // hover hit-test (screen space, nearest within 18px, prefer front)
      if (pointer.x >= 0) {
        let best = -1, bd = 18 * 18;
        for (const i of order) { const p = P[i]; const d = (p.X - pointer.x) ** 2 + (p.Y - pointer.y) ** 2; if (d < bd) { bd = d; best = i; } }
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
  }, []);

  return (
    <div ref={wrap} className="relative aspect-square w-full select-none">
      <canvas ref={canvas} data-hot className="h-full w-full touch-none" style={{ cursor: "grab" }} />
      <div className="hud pointer-events-none absolute left-4 top-4 text-[10px] uppercase tracking-[0.14em] text-faint">
        surface map · <span style={{ color: "var(--validated)" }}>live</span>
      </div>
      <div className="hud pointer-events-none absolute bottom-4 right-4 text-[10px] uppercase tracking-[0.12em] text-faint">drag to orbit · hover a node</div>
    </div>
  );
}
