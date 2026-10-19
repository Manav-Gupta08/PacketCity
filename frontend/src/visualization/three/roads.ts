import * as THREE from "three";

import type { PlazaSpec, RoadSpec, SceneModel } from "../iso/scene";
import { groundHeightFn, profileHeight } from "../iso/scene";
import { Batches, box, glowMaterial, groundBox, groundQuad, worldUV } from "./geom";

export const ROAD_Y = 0.6;
const MARK_Y = ROAD_Y + 0.06;
const ASPHALT_UV = 200;
const LAMP_SPACING = 95;
const LAMP_HEIGHT = 30;
const DASH = 14;
const GAP = 16;
const BARRIER_H = 2.6;
/** Long pieces of an elevated road are cut this short so they can bend over the ramps. */
const DECK_SEGMENT = 12;
const DECK_THICKNESS = 4;
const DECK_OVERHANG = 5;
const PILLAR_SPACING = 80;
const PILLAR_SIZE = 6;
/** Below this deck height a ramp rests on an embankment rather than pillars. */
const PILLAR_MIN_HEIGHT = 8;

interface Sink {
  add(material: THREE.Material, geometry: THREE.BufferGeometry): void;
}

const segmentsFor = (r: RoadSpec, len: number): number => (r.elevation ? Math.max(1, Math.ceil(len / DECK_SEGMENT)) : 1);

/** Forwards geometry to `b` after raising every vertex to the road's deck height at that point. */
function lifted(b: Batches, r: RoadSpec, u: THREE.Vector2, len: number): Sink {
  const e = r.elevation!;
  return {
    add(material, g) {
      const pos = g.getAttribute("position") as THREE.BufferAttribute;
      for (let i = 0; i < pos.count; i++) {
        const s = (pos.getX(i) - r.from.x) * u.x + (pos.getZ(i) - r.from.y) * u.y;
        pos.setY(i, pos.getY(i) + profileHeight(e, s, len));
      }
      g.computeVertexNormals();
      b.add(material, g);
    },
  };
}

export interface RoadTextures {
  asphalt: THREE.Texture;
  wetness: THREE.Texture;
  glow: THREE.Texture;
  arrow: THREE.Texture;
}

interface Mats {
  asphalt: THREE.MeshStandardMaterial;
  concrete: THREE.MeshStandardMaterial;
  metal: THREE.MeshStandardMaterial;
  paint: THREE.MeshBasicMaterial;
  lampHead: THREE.MeshBasicMaterial;
  pool: THREE.MeshBasicMaterial;
  arrow: Map<number, THREE.MeshBasicMaterial>;
  edge: Map<number, THREE.MeshBasicMaterial>;
}

function materials(tex: RoadTextures, env: THREE.Texture | null): Mats {
  return {
    asphalt: new THREE.MeshStandardMaterial({
      map: tex.asphalt,
      roughnessMap: tex.wetness,
      roughness: 0.55,
      metalness: 0.35,
      envMap: env,
      envMapIntensity: 0.9,
      color: 0xb0b8cc,
    }),
    concrete: new THREE.MeshStandardMaterial({ color: 0x2a3142, roughness: 0.7, metalness: 0.2, envMap: env, envMapIntensity: 0.4 }),
    metal: new THREE.MeshStandardMaterial({ color: 0x3a4256, roughness: 0.35, metalness: 0.8, envMap: env }),
    paint: new THREE.MeshBasicMaterial({ color: new THREE.Color(0xd8e6ff).multiplyScalar(0.9), toneMapped: false }),
    lampHead: glowMaterial(0xd6ecff, 2.4),
    pool: new THREE.MeshBasicMaterial({
      map: tex.glow,
      color: new THREE.Color(0x9fd4ff).multiplyScalar(0.5),
      blending: THREE.AdditiveBlending,
      transparent: true,
      depthWrite: false,
      toneMapped: false,
    }),
    arrow: new Map(),
    edge: new Map(),
  };
}

function tinted(map: Map<number, THREE.MeshBasicMaterial>, color: number, make: () => THREE.MeshBasicMaterial): THREE.MeshBasicMaterial {
  let m = map.get(color);
  if (!m) map.set(color, (m = make()));
  return m;
}

/** Dashed line along a road at lateral offset `off`. */
function dashes(b: Sink, m: THREE.Material, r: RoadSpec, u: THREE.Vector2, n: THREE.Vector2, len: number, off: number, width = 1): void {
  for (let s = 10; s + DASH < len - 10; s += DASH + GAP) {
    const c = s + DASH / 2;
    b.add(m, groundQuad(r.from.x + u.x * c + n.x * off, MARK_Y, r.from.y + u.y * c + n.y * off, u.x, u.y, DASH, width));
  }
}

function solid(b: Sink, m: THREE.Material, r: RoadSpec, u: THREE.Vector2, n: THREE.Vector2, len: number, off: number, width = 0.9, y = MARK_Y): void {
  const c = len / 2;
  b.add(m, groundQuad(r.from.x + u.x * c + n.x * off, y, r.from.y + u.y * c + n.y * off, u.x, u.y, len, width, segmentsFor(r, len)));
}

/** Concrete deck under an elevated road, neon trim along its underside, and pillars down to the ground. */
function deck(b: Batches, top: Sink, m: Mats, r: RoadSpec, u: THREE.Vector2, n: THREE.Vector2, len: number, edge: THREE.Material): void {
  const e = r.elevation!;
  const cx = (r.from.x + r.to.x) / 2;
  const cz = (r.from.y + r.to.y) / 2;
  const deckW = r.width + 2 * DECK_OVERHANG;
  const seg = segmentsFor(r, len);
  top.add(m.concrete, groundBox(cx, cz, u.x, u.y, len, deckW, -DECK_THICKNESS, DECK_THICKNESS, 0, seg));
  for (const side of [-1, 1]) {
    const off = side * (deckW / 2);
    top.add(edge, groundBox(cx + n.x * off, cz + n.y * off, u.x, u.y, len, 0.35, -DECK_THICKNESS * 0.6, 0.35, 0, seg));
  }
  const twin = r.width > 40;
  const spacing = Math.min(PILLAR_SPACING, len);
  for (let s = spacing / 2; s < len; s += spacing) {
    const h = profileHeight(e, s, len) - DECK_THICKNESS;
    if (h + DECK_THICKNESS < PILLAR_MIN_HEIGHT) continue;
    const px = r.from.x + u.x * s;
    const pz = r.from.y + u.y * s;
    for (const lat of twin ? [-r.width * 0.28, r.width * 0.28] : [0]) {
      b.add(m.concrete, groundBox(px + n.x * lat, pz + n.y * lat, u.x, u.y, PILLAR_SIZE, PILLAR_SIZE, 0, h));
    }
    b.add(m.concrete, groundBox(px, pz, n.x, n.y, r.width * 0.8, PILLAR_SIZE * 0.9, h - 3, 3));
    b.add(edge, groundBox(px, pz, n.x, n.y, r.width * 0.8 + 0.4, 0.3, h - 1.6, 0.3));
  }
}

function road(b: Batches, m: Mats, r: RoadSpec, tex: RoadTextures, overhead: (x: number, y: number) => number): void {
  const dir = new THREE.Vector2(r.to.x - r.from.x, r.to.y - r.from.y);
  const len = dir.length();
  if (len < 1) return;
  const u = dir.divideScalar(len);
  const out: Sink = r.elevation ? lifted(b, r, u, len) : b;
  roadSurface(b, out, m, r, tex, u, len, r.elevation ? () => 0 : overhead);
}

function roadSurface(raw: Batches, b: Sink, m: Mats, r: RoadSpec, tex: RoadTextures, u: THREE.Vector2, len: number, overhead: (x: number, y: number) => number): void {
  const seg = segmentsFor(r, len);
  // Right-hand normal (y-down ground plane): traffic along +u drives on the +n side.
  const n = new THREE.Vector2(-u.y, u.x);
  const cx = (r.from.x + r.to.x) / 2;
  const cz = (r.from.y + r.to.y) / 2;
  const half = r.width / 2;
  const median = r.median ?? 0;
  const lanes = r.lanesPerDirection;
  const laneW = (half - median / 2) / lanes;
  const edgeColor = r.tint;
  const edge = tinted(m.edge, edgeColor, () => glowMaterial(edgeColor, 1.3));

  b.add(m.asphalt, groundBox(cx, cz, u.x, u.y, len + (r.style === "drive" ? 0 : r.width * 0.5), r.width, 0, ROAD_Y, ASPHALT_UV, seg));
  if (r.elevation) deck(raw, b, m, r, u, n, len, edge);

  if (r.style !== "drive") {
    for (const side of [-1, 1]) {
      for (let k = 1; k < lanes; k++) dashes(b, m.paint, r, u, n, len, side * (median / 2 + k * laneW), 0.8);
      solid(b, m.paint, r, u, n, len, side * (half - 1.6), 0.7);
    }
  }

  if (median > 0) {
    b.add(m.concrete, groundBox(cx, cz, u.x, u.y, len, median * 0.55, ROAD_Y, 1.6, 0, seg));
    b.add(edge, groundBox(cx, cz, u.x, u.y, len, 0.5, ROAD_Y + 1.6, 0.35, 0, seg));
  } else if (r.style === "street") {
    dashes(b, tinted(m.edge, 0xffb020, () => glowMaterial(0xffb020, 1.6)), r, u, n, len, 0, 0.9);
  }

  if (r.style === "highway") {
    for (const side of [-1, 1]) {
      const off = side * (half + 0.7);
      const ox = cx + n.x * off;
      const oz = cz + n.y * off;
      b.add(m.concrete, groundBox(ox, oz, u.x, u.y, len, 1.4, 0, BARRIER_H, 0, seg));
      b.add(edge, groundBox(ox, oz, u.x, u.y, len, 0.25, BARRIER_H, 0.25, 0, seg));
    }
  } else if (r.style === "street") {
    for (const side of [-1, 1]) {
      const off = side * (half + 5);
      b.add(m.concrete, groundBox(cx + n.x * off, cz + n.y * off, u.x, u.y, len, 10, 0, 1.1, 0, seg));
      b.add(edge, groundBox(cx + n.x * side * (half + 0.2), cz + n.y * side * (half + 0.2), u.x, u.y, len, 0.3, 1.1, 0.25, 0, seg));
    }
  } else {
    for (const side of [-1, 1]) solid(b, edge, r, u, n, len, side * (half - 0.5), 0.6, MARK_Y + 0.02);
  }

  // Direction arrows and lane lighting per carriageway (+n side flows along u).
  if (r.flowTints) {
    r.flowTints.forEach((tint, k) => {
      const side = k === 0 ? 1 : -1;
      const arrowMat = tinted(m.arrow, tint, () =>
        new THREE.MeshBasicMaterial({ map: tex.arrow, color: new THREE.Color(tint).multiplyScalar(1.6), transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, toneMapped: false }),
      );
      const flowX = k === 0 ? u.x : -u.x;
      const flowY = k === 0 ? u.y : -u.y;
      for (let s = 60; s < len - 60; s += 170) {
        for (let lane = 0; lane < lanes; lane++) {
          const off = side * (median / 2 + laneW * (lane + 0.5));
          // Arrow texture points +V; the quad's long axis runs along the flow.
          const g = new THREE.PlaneGeometry(laneW * 0.5, 16);
          g.rotateX(-Math.PI / 2);
          g.rotateY(Math.atan2(-flowY, flowX) - Math.PI / 2);
          g.translate(r.from.x + u.x * s + n.x * off, MARK_Y + 0.01, r.from.y + u.y * s + n.y * off);
          b.add(arrowMat, g.toNonIndexed());
        }
      }
      const glow = tinted(m.edge, tint, () => glowMaterial(tint, 2.2));
      solid(b, glow, r, u, n, len, side * (median / 2 + 0.9), 0.35, MARK_Y + 0.015);
    });
  }

  if (r.style === "highway" || r.style === "street") {
    for (let s = LAMP_SPACING / 2; s < len; s += LAMP_SPACING) {
      for (const side of [-1, 1]) {
        if (r.style === "street" && side < 0 && Math.round(s / LAMP_SPACING) % 2 === 0) continue;
        const base = side * (half + (r.style === "highway" ? 3 : 7));
        const px = r.from.x + u.x * s + n.x * base;
        const pz = r.from.y + u.y * s + n.y * base;
        if (overhead(px, pz) > 0 || overhead(px + n.x * side * -9, pz + n.y * side * -9) > 0) continue;
        b.add(m.metal, box(px, LAMP_HEIGHT / 2, pz, 1.2, LAMP_HEIGHT, 1.2));
        const arm = side * -9;
        const ax = px + n.x * arm / 2;
        const az = pz + n.y * arm / 2;
        b.add(m.metal, groundBox(ax, az, n.x, n.y, 10, 0.8, LAMP_HEIGHT - 0.8, 0.8));
        const hx = px + n.x * arm;
        const hz = pz + n.y * arm;
        b.add(m.lampHead, groundBox(hx, hz, u.x, u.y, 5, 1.6, LAMP_HEIGHT - 1.5, 0.7));
        b.add(m.pool, groundQuad(hx, MARK_Y + 0.03, hz, u.x, u.y, 58, 46));
      }
    }
  }

  if (r.style === "highway" && len > 420) gantry(b, m, r, u, n, len * 0.34, half, edgeColor);
}

/** Overhead sign gantry spanning the highway. */
function gantry(b: Sink, m: Mats, r: RoadSpec, u: THREE.Vector2, n: THREE.Vector2, s: number, half: number, tint: number): void {
  const px = r.from.x + u.x * s;
  const pz = r.from.y + u.y * s;
  const span = half * 2 + 12;
  const h = 44;
  for (const side of [-1, 1]) b.add(m.metal, box(px + n.x * side * (span / 2), h / 2, pz + n.y * side * (span / 2), 2.4, h, 2.4));
  b.add(m.metal, groundBox(px, pz, n.x, n.y, span + 3, 3, h, 3));
  b.add(m.metal, groundBox(px, pz, n.x, n.y, span + 3, 1.2, h - 7, 1.2));
  const panel = tinted(m.edge, tint, () => glowMaterial(tint, 2.2));
  for (const side of [-1, 1]) {
    const off = side * half * 0.5;
    b.add(m.concrete, groundBox(px + n.x * off + u.x * 1.5, pz + n.y * off + u.y * 1.5, n.x, n.y, half * 0.8, 0.8, h - 8, 7));
    b.add(panel, groundBox(px + n.x * off + u.x * 2, pz + n.y * off + u.y * 2, n.x, n.y, half * 0.76, 0.2, h - 7.5, 6));
  }
}

function plaza(b: Batches, m: Mats, p: PlazaSpec, group: THREE.Group): void {
  const edge = tinted(m.edge, p.tint, () => glowMaterial(p.tint, 2.4));
  if (p.ring) {
    const rad = Math.min(p.w, p.d) / 2;
    const disk = new THREE.CylinderGeometry(rad, rad, ROAD_Y, 48).toNonIndexed();
    disk.translate(p.gx, ROAD_Y / 2, p.gy);
    worldUV(disk, ASPHALT_UV);
    b.add(m.asphalt, disk);
    const ring = new THREE.RingGeometry(rad - 1.6, rad - 0.6, 64);
    ring.rotateX(-Math.PI / 2);
    ring.translate(p.gx, MARK_Y + 0.02, p.gy);
    b.add(edge, ring.toNonIndexed());
    const island = rad * 0.32;
    const isle = new THREE.CylinderGeometry(island, island + 2, 2.2, 40).toNonIndexed();
    isle.translate(p.gx, ROAD_Y + 1.1, p.gy);
    b.add(m.concrete, isle);
    const lip = new THREE.TorusGeometry(island + 1, 0.45, 6, 48);
    lip.rotateX(Math.PI / 2);
    lip.translate(p.gx, ROAD_Y + 2.3, p.gy);
    b.add(edge, lip.toNonIndexed());
    for (let k = 0; k < 24; k++) {
      const a = (k / 24) * Math.PI * 2;
      const rr = rad * 0.66;
      const g = new THREE.PlaneGeometry(6, 1.1);
      g.rotateX(-Math.PI / 2);
      g.rotateY(-a);
      g.translate(p.gx + Math.cos(a) * rr, MARK_Y, p.gy + Math.sin(a) * rr);
      b.add(m.paint, g.toNonIndexed());
    }
    const glow = new THREE.Mesh(
      new THREE.PlaneGeometry(rad * 2.6, rad * 2.6),
      new THREE.MeshBasicMaterial({ map: m.pool.map, color: new THREE.Color(p.tint).multiplyScalar(0.28), blending: THREE.AdditiveBlending, transparent: true, depthWrite: false, toneMapped: false }),
    );
    glow.rotation.x = -Math.PI / 2;
    glow.position.set(p.gx, MARK_Y + 0.04, p.gy);
    group.add(glow);
    return;
  }
  b.add(m.concrete, groundBox(p.gx, p.gy, 1, 0, p.w, p.d, 0, ROAD_Y + 0.3));
  for (let x = -p.w / 2 + 10; x < p.w / 2; x += 20) solid(b, edge, { from: { x: p.gx + x, y: p.gy - p.d / 2 }, to: { x: p.gx + x, y: p.gy + p.d / 2 } } as RoadSpec, new THREE.Vector2(0, 1), new THREE.Vector2(-1, 0), p.d, 0, 0.3, ROAD_Y + 0.35);
  for (const s of [-1, 1]) {
    b.add(edge, groundBox(p.gx, p.gy + (s * p.d) / 2, 1, 0, p.w, 0.6, ROAD_Y + 0.3, 0.5));
    b.add(edge, groundBox(p.gx + (s * p.w) / 2, p.gy, 0, 1, p.d, 0.6, ROAD_Y + 0.3, 0.5));
  }
}

export function buildRoads(model: SceneModel, tex: RoadTextures, env: THREE.Texture | null): THREE.Group {
  const group = new THREE.Group();
  group.name = "roads";
  const m = materials(tex, env);
  const b = new Batches();
  const overhead = groundHeightFn(model.roads);
  for (const r of model.roads) road(b, m, r, tex, overhead);
  for (const p of model.plazas) plaza(b, m, p, group);
  b.build(group);
  return group;
}
