import { useEffect, useRef } from 'react';

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  alpha: number;
}

interface Signal {
  fromIdx: number;
  toIdx: number;
  t: number;      // 0..1 travel progress
  speed: number;
  critical: boolean;
}

/**
 * NetworkCanvas — a lightweight Canvas2D atmospheric background.
 * Renders abstract network topology: faint olive/terracotta nodes,
 * thin warm connection lines, small signal dots traveling edges.
 * Adapted for light (terracotta/olive) theme.
 * Sits behind all UI (z-index: 0), pointer-events: none.
 */
export function NetworkCanvas({ className = '' }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    let W = 0, H = 0;
    const NODES = 32;
    const MAX_DIST = 200;
    const nodes: Node[] = [];
    const signals: Signal[] = [];
    let lastSignal = 0;

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function resize() {
      const canvas = canvasRef.current;
      if (!canvas || !ctx) return;
      W = canvas.offsetWidth;
      H = canvas.offsetHeight;
      canvas.width = W * devicePixelRatio;
      canvas.height = H * devicePixelRatio;
      ctx.scale(devicePixelRatio, devicePixelRatio);
    }

    function init() {
      nodes.length = 0;
      signals.length = 0;
      for (let i = 0; i < NODES; i++) {
        nodes.push({
          x: Math.random() * W,
          y: Math.random() * H,
          vx: (Math.random() - .5) * .16,
          vy: (Math.random() - .5) * .16,
          r: 1.0 + Math.random() * 1.4,
          alpha: .10 + Math.random() * .16,
        });
      }
    }

    function dist(a: Node, b: Node) {
      return Math.hypot(a.x - b.x, a.y - b.y);
    }

    function spawnSignal(now: number) {
      if (now - lastSignal < 2000) return;
      lastSignal = now;
      const fromIdx = Math.floor(Math.random() * nodes.length);
      let toIdx = fromIdx;
      for (let tries = 0; tries < 20; tries++) {
        const candidate = Math.floor(Math.random() * nodes.length);
        if (candidate !== fromIdx && dist(nodes[fromIdx], nodes[candidate]) < MAX_DIST) {
          toIdx = candidate;
          break;
        }
      }
      if (toIdx === fromIdx) return;
      signals.push({
        fromIdx,
        toIdx,
        t: 0,
        speed: .003 + Math.random() * .004,
        critical: Math.random() < .18,
      });
    }

    function draw(now: number) {
      if (!ctx) return;
      ctx.clearRect(0, 0, W, H);

      // Soft terracotta radial glow from center — very faint on light bg
      const grd = ctx.createRadialGradient(W * .5, H * .44, 0, W * .5, H * .44, Math.max(W, H) * .55);
      grd.addColorStop(0,   'rgba(216,115,85,.018)');
      grd.addColorStop(.4,  'rgba(216,115,85,.008)');
      grd.addColorStop(1,   'rgba(0,0,0,0)');
      ctx.fillStyle = grd;
      ctx.fillRect(0, 0, W, H);

      // Move nodes
      for (const n of nodes) {
        if (!prefersReduced) {
          n.x += n.vx;
          n.y += n.vy;
          if (n.x < -30) n.x = W + 30;
          if (n.x > W + 30) n.x = -30;
          if (n.y < -30) n.y = H + 30;
          if (n.y > H + 30) n.y = -30;
        }
      }

      // Draw edges — warm olive tint on light bg
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const d = dist(nodes[i], nodes[j]);
          if (d > MAX_DIST) continue;
          const a = (1 - d / MAX_DIST) * .06;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = `rgba(139,134,92,${a.toFixed(3)})`;
          ctx.lineWidth = .5;
          ctx.stroke();
        }
      }

      // Draw nodes — olive dots
      for (const n of nodes) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(139,134,92,${n.alpha.toFixed(2)})`;
        ctx.fill();
      }

      // Signals
      if (!prefersReduced) spawnSignal(now);

      for (let si = signals.length - 1; si >= 0; si--) {
        const s = signals[si];
        s.t += s.speed;
        if (s.t >= 1) { signals.splice(si, 1); continue; }
        const from = nodes[s.fromIdx];
        const to   = nodes[s.toIdx];
        const sx = from.x + (to.x - from.x) * s.t;
        const sy = from.y + (to.y - from.y) * s.t;
        // critical → terracotta, normal → olive
        const color = s.critical ? 'rgba(216,115,85,' : 'rgba(139,134,92,';
        const fade = s.t < .2 ? s.t / .2 : s.t > .8 ? (1 - s.t) / .2 : 1;

        // Glow halo
        ctx.beginPath();
        ctx.arc(sx, sy, 4, 0, Math.PI * 2);
        ctx.fillStyle = `${color}${(0.06 * fade).toFixed(3)})`;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(sx, sy, s.critical ? 2 : 1.4, 0, Math.PI * 2);
        ctx.fillStyle = `${color}${(0.55 * fade).toFixed(3)})`;
        ctx.fill();
      }

      animId = requestAnimationFrame(draw);
    }

    const ro = new ResizeObserver(() => {
      resize();
    });
    if (canvas.parentElement) ro.observe(canvas.parentElement);

    resize();
    init();
    animId = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animId);
      ro.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className={`pointer-events-none ${className}`}
      aria-hidden="true"
      style={{ display: 'block', width: '100%', height: '100%' }}
    />
  );
}
