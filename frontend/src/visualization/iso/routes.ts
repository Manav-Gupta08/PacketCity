import { headingOf, type Heading, type Pt } from "./projection";

/** A drivable polyline in ground coordinates with precomputed cumulative lengths. */
export interface Route {
  xs: Float32Array;
  ys: Float32Array;
  cum: Float32Array;
  length: number;
}

export interface RouteSample {
  x: number;
  y: number;
  heading: Heading;
  /** Exact travel direction in the ground plane, radians (atan2(dy, dx)). */
  angle: number;
}

function dedupe(points: readonly Pt[]): Pt[] {
  const out: Pt[] = [];
  for (const p of points) {
    const last = out[out.length - 1];
    if (!last || Math.abs(last.x - p.x) > 1e-6 || Math.abs(last.y - p.y) > 1e-6) out.push(p);
  }
  return out;
}

function unitNormal(a: Pt, b: Pt): Pt {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = Math.hypot(dx, dy) || 1;
  // Right-hand normal in a y-down plane: facing +x, the right side is +y.
  return { x: -dy / len, y: dx / len };
}

/**
 * Builds a route offset `offset` units to the right of travel (right-hand traffic).
 * Corners use a miter so lanes stay parallel through turns.
 */
export function buildRoute(points: readonly Pt[], offset: number): Route {
  const p = dedupe(points);
  const n = p.length;
  const xs = new Float32Array(Math.max(n, 1));
  const ys = new Float32Array(Math.max(n, 1));
  for (let i = 0; i < n; i++) {
    const nIn = i > 0 ? unitNormal(p[i - 1]!, p[i]!) : null;
    const nOut = i < n - 1 ? unitNormal(p[i]!, p[i + 1]!) : null;
    let ox: number;
    let oy: number;
    if (nIn && nOut) {
      const dot = nIn.x * nOut.x + nIn.y * nOut.y;
      // A U-turn has no finite miter; fall back to the incoming normal.
      const k = dot > -0.99 ? 1 / (1 + dot) : 0;
      ox = k ? (nIn.x + nOut.x) * k : nIn.x;
      oy = k ? (nIn.y + nOut.y) * k : nIn.y;
    } else {
      const nn = nIn ?? nOut;
      ox = nn?.x ?? 0;
      oy = nn?.y ?? 0;
    }
    xs[i] = p[i]!.x + ox * offset;
    ys[i] = p[i]!.y + oy * offset;
  }
  const cum = new Float32Array(Math.max(n, 1));
  for (let i = 1; i < n; i++) cum[i] = cum[i - 1]! + Math.hypot(xs[i]! - xs[i - 1]!, ys[i]! - ys[i - 1]!);
  return { xs, ys, cum, length: n > 1 ? cum[n - 1]! : 0 };
}

/** Position and heading at `dist` along the route (clamped to its ends). */
export function sampleRoute(r: Route, dist: number, out: RouteSample): RouteSample {
  const n = r.xs.length;
  if (n < 2) {
    out.x = r.xs[0] ?? 0;
    out.y = r.ys[0] ?? 0;
    return out;
  }
  const d = Math.min(Math.max(dist, 0), r.length);
  let i = 1;
  while (i < n - 1 && r.cum[i]! < d) i++;
  const segLen = r.cum[i]! - r.cum[i - 1]! || 1;
  const t = (d - r.cum[i - 1]!) / segLen;
  const dx = r.xs[i]! - r.xs[i - 1]!;
  const dy = r.ys[i]! - r.ys[i - 1]!;
  out.x = r.xs[i - 1]! + dx * t;
  out.y = r.ys[i - 1]! + dy * t;
  out.heading = headingOf(dx, dy);
  out.angle = Math.atan2(dy, dx);
  return out;
}

/**
 * Joins two node→hub paths into one src→dst path, turning at the first shared waypoint so that
 * neighbours on the same street don't drive to the hub and back.
 */
export function joinPaths(srcToHub: readonly Pt[], dstToHub: readonly Pt[]): Pt[] {
  const same = (a: Pt, b: Pt) => Math.abs(a.x - b.x) < 1e-6 && Math.abs(a.y - b.y) < 1e-6;
  let i = srcToHub.length - 1;
  let j = dstToHub.length - 1;
  while (i > 0 && j > 0 && same(srcToHub[i - 1]!, dstToHub[j - 1]!)) {
    i--;
    j--;
  }
  return [...srcToHub.slice(0, i + 1), ...dstToHub.slice(0, j).reverse()];
}
