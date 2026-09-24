import * as THREE from "three";

import type { BuildingSpec, SceneModel } from "../iso/scene";
import { hash01 } from "../iso/scene";
import { Batches, box, facadeBox, glowMaterial } from "./geom";
import { rng, type Facade, type FacadePalette } from "./textures";

export interface CityTextures {
  facades: Record<FacadePalette, Facade>;
  ads: THREE.Texture[];
  glow: THREE.Texture;
}

/** Something that moves every frame (holograms, beacons, flickering ads). */
export interface Animated {
  update(t: number): void;
}

export interface City {
  group: THREE.Group;
  /** Invisible hit boxes for interactive buildings; `userData.node` is the map node. */
  pickables: THREE.Mesh[];
  animated: Animated[];
  /** World-space top of each landmark, by node. */
  anchors: Map<string, THREE.Vector3>;
  /** Where a holographic label floats above each landmark, keyed by `posKey(gx, gy)`. */
  labels: Map<string, THREE.Vector3>;
}

export const posKey = (gx: number, gy: number): string => `${Math.round(gx)},${Math.round(gy)}`;

interface Mats {
  facade: Record<FacadePalette, THREE.MeshStandardMaterial>;
  /** Background buildings: no PBR/env reflections, much cheaper per pixel. */
  facadeCheap: Record<FacadePalette, THREE.MeshLambertMaterial>;
  trim: THREE.MeshStandardMaterial;
  roof: THREE.MeshStandardMaterial;
  glow: Map<number, THREE.MeshBasicMaterial>;
  red: THREE.MeshBasicMaterial;
  pick: THREE.MeshBasicMaterial;
  /** Holographic billboards left to place (each is its own draw call). */
  adBudget: number;
}

function makeMats(tex: CityTextures, env: THREE.Texture | null, adBudget = 24): Mats {
  const facade = (p: FacadePalette) =>
    new THREE.MeshStandardMaterial({
      map: tex.facades[p].map,
      emissiveMap: tex.facades[p].emissive,
      emissive: 0xffffff,
      emissiveIntensity: 1.35,
      roughness: 0.22,
      metalness: 0.75,
      envMap: env,
      envMapIntensity: 1.1,
    });
  const cheap = (p: FacadePalette) =>
    new THREE.MeshLambertMaterial({ map: tex.facades[p].map, emissiveMap: tex.facades[p].emissive, emissive: 0xffffff, emissiveIntensity: 1.0, color: 0x8a96b8 });
  return {
    facade: { warm: facade("warm"), cool: facade("cool"), neon: facade("neon") },
    facadeCheap: { warm: cheap("warm"), cool: cheap("cool"), neon: cheap("neon") },
    trim: new THREE.MeshStandardMaterial({ color: 0x2b3345, roughness: 0.4, metalness: 0.85, envMap: env }),
    roof: new THREE.MeshStandardMaterial({ color: 0x141a28, roughness: 0.6, metalness: 0.5, envMap: env }),
    glow: new Map(),
    red: glowMaterial(0xff2a3a, 4),
    pick: new THREE.MeshBasicMaterial({ visible: false }),
    adBudget,
  };
}

function glow(m: Mats, color: number, intensity = 2.6): THREE.MeshBasicMaterial {
  const key = color * 10 + intensity;
  let mat = m.glow.get(key);
  if (!mat) m.glow.set(key, (mat = glowMaterial(color, intensity)));
  return mat;
}

/** Neon outline around a footprint at height y (four thin bars). */
function crown(b: Batches, mat: THREE.Material, cx: number, cz: number, w: number, d: number, y: number, t = 0.7): void {
  b.add(mat, box(cx, y, cz - d / 2, w + t, t, t));
  b.add(mat, box(cx, y, cz + d / 2, w + t, t, t));
  b.add(mat, box(cx - w / 2, y, cz, t, t, d + t));
  b.add(mat, box(cx + w / 2, y, cz, t, t, d + t));
}

function antenna(b: Batches, m: Mats, x: number, y: number, z: number, h: number): void {
  b.add(m.trim, box(x, y + h / 2, z, 1, h, 1));
  b.add(m.trim, box(x, y + h * 0.35, z, 5, 0.6, 0.6));
  b.add(m.red, box(x, y + h + 0.8, z, 1.8, 1.8, 1.8));
}

function roofClutter(b: Batches, m: Mats, r: () => number, cx: number, cz: number, w: number, d: number, y: number): void {
  const n = 1 + Math.floor(r() * 3);
  for (let i = 0; i < n; i++) {
    const bw = 6 + r() * w * 0.25;
    const bd = 6 + r() * d * 0.25;
    b.add(m.trim, box(cx + (r() - 0.5) * (w - bw), y + 2.5, cz + (r() - 0.5) * (d - bd), bw, 5, bd));
  }
}

/** Vertical LED strips on the two faces that face the default camera (+X and +Z). */
function ledStrips(b: Batches, mat: THREE.Material, cx: number, cz: number, w: number, d: number, y0: number, h: number, count: number): void {
  for (let i = 0; i < count; i++) {
    const t = (i + 1) / (count + 1);
    b.add(mat, box(cx + w / 2 + 0.35, y0 + h / 2, cz - d / 2 + d * t, 0.5, h, 1.1));
    b.add(mat, box(cx - w / 2 + w * t, y0 + h / 2, cz + d / 2 + 0.35, 1.1, h, 0.5));
  }
}

function hologramPanel(group: THREE.Group, tex: THREE.Texture, x: number, y: number, z: number, w: number, h: number, facing: "x" | "z", animated: Animated[], seed: number): void {
  const mat = new THREE.MeshBasicMaterial({ map: tex, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, toneMapped: false, side: THREE.DoubleSide, opacity: 0.95 });
  mat.color.setScalar(1.6);
  const mesh = new THREE.Mesh(new THREE.PlaneGeometry(w, h), mat);
  mesh.position.set(x, y, z);
  if (facing === "x") mesh.rotation.y = Math.PI / 2;
  group.add(mesh);
  const phase = seed * 1.7;
  animated.push({
    update(t) {
      // Mostly steady with an occasional holographic stutter.
      const flicker = Math.sin(t * 23 + phase) > 0.985 ? 0.35 : 1;
      mat.opacity = (0.82 + 0.12 * Math.sin(t * 1.3 + phase)) * flicker;
    },
  });
}

function decor(b: Batches, m: Mats, tex: CityTextures, s: BuildingSpec, group: THREE.Group, animated: Animated[]): void {
  const seed = Math.round(s.gx * 7 + s.gy * 13);
  const r = rng(seed);
  const palettes: FacadePalette[] = ["cool", "warm", "neon"];
  const facade = m.facadeCheap[palettes[Math.floor(hash01(Math.round(s.gx), Math.round(s.gy)) * 3)]!];
  const accent = glow(m, s.tint);
  const uo = r() * 400;
  const kind = r();
  const { gx, gy, w, d, h } = s;

  if (h > 120 && kind < 0.4) {
    // Setback glass tower with crown and antenna.
    const h1 = h * 0.68;
    b.add(facade, facadeBox(gx, 0, gy, w, h1, d, uo));
    const w2 = w * 0.72;
    const d2 = d * 0.72;
    b.add(facade, facadeBox(gx, h1, gy, w2, h - h1, d2, uo + 37));
    crown(b, accent, gx, gy, w, d, h1 + 0.4);
    crown(b, accent, gx, gy, w2, d2, h + 0.4);
    b.add(m.roof, box(gx, h + 0.3, gy, w2 * 0.9, 0.6, d2 * 0.9));
    antenna(b, m, gx + w2 * 0.2, h, gy - d2 * 0.1, 18 + r() * 30);
  } else if (kind < 0.62) {
    // Slab with vertical LED strips.
    b.add(facade, facadeBox(gx, 0, gy, w, h, d, uo));
    ledStrips(b, accent, gx, gy, w, d, 4, h - 6, 1 + Math.floor(r() * 3));
    b.add(m.roof, box(gx, h + 0.4, gy, w * 0.94, 0.8, d * 0.94));
    roofClutter(b, m, r, gx, gy, w, d, h);
  } else if (kind < 0.8 && h > 50 && m.adBudget > 0) {
    // Commercial block with a holographic billboard.
    m.adBudget--;
    b.add(facade, facadeBox(gx, 0, gy, w, h, d, uo));
    b.add(m.roof, box(gx, h + 0.4, gy, w * 0.94, 0.8, d * 0.94));
    crown(b, accent, gx, gy, w, d, h + 0.9, 0.5);
    const ad = tex.ads[Math.floor(r() * tex.ads.length)]!;
    const onX = r() < 0.5;
    const pw = (onX ? d : w) * 0.82;
    const ph = Math.min(h * 0.32, pw * 0.5);
    const py = h - ph / 2 - 4;
    if (onX) hologramPanel(group, ad, gx + w / 2 + 2, py, gy, pw, ph, "x", animated, seed);
    else hologramPanel(group, ad, gx, py, gy + d / 2 + 2, pw, ph, "z", animated, seed);
  } else if (h < 110) {
    // Data centre: wide, low, cooling units and light bands.
    b.add(facade, facadeBox(gx, 0, gy, w, h, d, uo));
    b.add(m.roof, box(gx, h + 0.4, gy, w * 0.96, 0.8, d * 0.96));
    for (let i = 0; i < 4; i++) b.add(m.trim, box(gx - w * 0.3 + (i % 2) * w * 0.6, h + 4, gy - d * 0.25 + Math.floor(i / 2) * d * 0.5, w * 0.24, 7, d * 0.2));
    crown(b, accent, gx, gy, w, d, h * 0.33, 0.45);
    crown(b, accent, gx, gy, w, d, h * 0.66, 0.45);
  } else {
    // Twin towers joined by a sky bridge.
    const tw = w * 0.42;
    const h2 = h * (0.75 + r() * 0.2);
    b.add(facade, facadeBox(gx - w * 0.29, 0, gy, tw, h, d * 0.8, uo));
    b.add(facade, facadeBox(gx + w * 0.29, 0, gy, tw, h2, d * 0.8, uo + 50));
    b.add(m.trim, box(gx, h2 * 0.62, gy, w * 0.2, 6, d * 0.3));
    b.add(accent, box(gx, h2 * 0.62 - 3.2, gy, w * 0.2, 0.5, d * 0.32));
    crown(b, accent, gx - w * 0.29, gy, tw, d * 0.8, h + 0.4);
    antenna(b, m, gx - w * 0.29, h, gy, 14 + r() * 20);
  }
}

/** Additive vertical light column rising from a landmark. */
function beam(group: THREE.Group, x: number, z: number, y0: number, height: number, radius: number, color: number, animated: Animated[]): void {
  const g = new THREE.CylinderGeometry(radius * 0.6, radius, height, 24, 1, true);
  g.translate(0, height / 2, 0);
  const mat = new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    side: THREE.DoubleSide,
    toneMapped: false,
    uniforms: { uColor: { value: new THREE.Color(color) }, uTime: { value: 0 } },
    vertexShader: "varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }",
    fragmentShader: `uniform vec3 uColor; uniform float uTime; varying vec2 vUv;
void main(){ float fade = pow(1.0 - vUv.y, 1.6); float bands = 0.75 + 0.25 * sin(vUv.y * 60.0 - uTime * 4.0);
gl_FragColor = vec4(uColor * fade * bands * 0.55, 1.0); }`,
  });
  const mesh = new THREE.Mesh(g, mat);
  mesh.position.set(x, y0, z);
  group.add(mesh);
  animated.push({ update: (t) => (mat.uniforms.uTime!.value = t) });
}

/** Rotating holographic rings hovering above a landmark. */
function haloRings(group: THREE.Group, x: number, y: number, z: number, radius: number, color: number, animated: Animated[]): void {
  const mat = glowMaterial(color, 2.4, { additive: true });
  const rings = new THREE.Group();
  rings.position.set(x, y, z);
  for (let i = 0; i < 3; i++) {
    const t = new THREE.Mesh(new THREE.TorusGeometry(radius * (1 - i * 0.18), 0.6 - i * 0.12, 6, 64), mat);
    t.rotation.x = Math.PI / 2 + (i - 1) * 0.28;
    rings.add(t);
  }
  group.add(rings);
  animated.push({ update: (t) => (rings.rotation.y = t * 0.4) });
}

function pickBox(pickables: THREE.Mesh[], group: THREE.Group, m: Mats, node: string, s: BuildingSpec, h: number): void {
  const mesh = new THREE.Mesh(new THREE.BoxGeometry(s.w * 1.05, h, s.d * 1.05), m.pick);
  mesh.position.set(s.gx, h / 2, s.gy);
  mesh.userData.node = node;
  group.add(mesh);
  pickables.push(mesh);
}

function landmark(b: Batches, m: Mats, tex: CityTextures, s: BuildingSpec, city: City): void {
  const { group, animated, pickables, anchors } = city;
  const { gx, gy, w, d, h } = s;
  const accent = glow(m, s.tint, 3);
  const node = s.node!;
  const label = (y: number) => city.labels.set(posKey(gx, gy), new THREE.Vector3(gx, y, gy));
  switch (s.kind) {
    case "self": {
      // YOUR DEVICE: a tall stepped tower with a cyan crown, halo and beacon beam.
      b.add(m.trim, box(gx, 3, gy, w + 8, 6, d + 8));
      b.add(m.facade.cool, facadeBox(gx, 6, gy, w, h * 0.62, d, 11));
      b.add(m.facade.cool, facadeBox(gx, 6 + h * 0.62, gy, w * 0.74, h * 0.3, d * 0.74, 71));
      const top = 6 + h * 0.92;
      crown(b, accent, gx, gy, w, d, 6 + h * 0.62, 1);
      crown(b, accent, gx, gy, w * 0.74, d * 0.74, top, 1);
      ledStrips(b, accent, gx, gy, w, d, 8, h * 0.6, 2);
      b.add(m.trim, box(gx, top + 6, gy, w * 0.4, 12, d * 0.4));
      haloRings(group, gx, top + 34, gy, w * 0.42, s.tint, animated);
      beam(group, gx, gy, top + 12, 420, 9, s.tint, animated);
      anchors.set(node, new THREE.Vector3(gx, top, gy));
      label(top + 62);
      pickBox(pickables, group, m, node, s, top + 20);
      break;
    }
    case "router": {
      // ROUTER: interchange control tower with rotating rings.
      const tower = h * 0.9;
      b.add(m.trim, box(gx, 4, gy, w, 8, d));
      b.add(m.facade.neon, facadeBox(gx, 8, gy, w * 0.55, tower, d * 0.55, 23));
      const top = 8 + tower;
      b.add(m.trim, box(gx, top + 4, gy, w * 0.95, 8, d * 0.95));
      crown(b, accent, gx, gy, w * 0.95, d * 0.95, top + 8.3, 1);
      crown(b, accent, gx, gy, w * 0.55, d * 0.55, top * 0.5, 0.8);
      antenna(b, m, gx, top + 8, gy, 30);
      haloRings(group, gx, top + 22, gy, w * 0.62, s.tint, animated);
      beam(group, gx, gy, top + 8, 360, 7, s.tint, animated);
      anchors.set(node, new THREE.Vector3(gx, top, gy));
      label(top + 44);
      pickBox(pickables, group, m, node, s, top + 12);
      break;
    }
    case "internet": {
      // INTERNET: a gateway arch over the road with a wireframe globe, backed by megatowers.
      const pylon = Math.min(w, d) * 0.28;
      const span = w * 0.5;
      for (const side of [-1, 1]) {
        b.add(m.facade.neon, facadeBox(gx + side * span, 0, gy, pylon, h, pylon, 90 + side * 30));
        crown(b, accent, gx + side * span, gy, pylon, pylon, h * 0.5, 0.8);
        crown(b, accent, gx + side * span, gy, pylon, pylon, h + 0.4, 0.8);
      }
      b.add(m.trim, box(gx, h - 6, gy, span * 2 + pylon, 12, pylon * 0.6));
      b.add(accent, box(gx, h - 12.4, gy, span * 2 + pylon, 0.8, pylon * 0.62));
      b.add(accent, box(gx, h + 0.4, gy, span * 2 + pylon, 0.8, pylon * 0.62));
      const globe = new THREE.Mesh(new THREE.IcosahedronGeometry(46, 2), new THREE.MeshBasicMaterial({ color: new THREE.Color(s.tint).multiplyScalar(2), wireframe: true, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false, toneMapped: false }));
      globe.position.set(gx, h + 70, gy);
      group.add(globe);
      animated.push({ update: (t) => (globe.rotation.y = t * 0.15) });
      haloRings(group, gx, h + 70, gy, 62, 0x00e5ff, animated);
      // Distant megatower cluster behind the gate (away from the road).
      const back = rng(99);
      for (let i = 0; i < 7; i++) {
        const bw = 40 + back() * 40;
        const bh = 260 + back() * 360;
        const bx = gx + (i - 3) * 70 + (back() - 0.5) * 20;
        const bz = gy - d / 2 - 90 - back() * 140;
        b.add(m.facade[i % 2 ? "cool" : "neon"], facadeBox(bx, 0, bz, bw, bh, bw, i * 41));
        crown(b, glow(m, i % 2 ? 0x00e5ff : 0xff2ea6, 2.6), bx, bz, bw, bw, bh + 0.4, 0.8);
        if (back() < 0.6) antenna(b, m, bx, bh, bz, 30 + back() * 40);
      }
      anchors.set(node, new THREE.Vector3(gx, h, gy));
      label(h + 136);
      pickBox(pickables, group, m, node, s, h + 110);
      break;
    }
    case "device": {
      // LAN device facility: faceted tower, tinted crown, door light facing the drive.
      const r = rng(Math.round(gx * 3 + gy * 5));
      b.add(m.trim, box(gx, 2, gy, w + 6, 4, d + 6));
      const pal: FacadePalette = r() < 0.5 ? "cool" : "neon";
      b.add(m.facade[pal], facadeBox(gx, 4, gy, w, h - 4, d, r() * 300));
      crown(b, accent, gx, gy, w, d, h + 0.4, 0.8);
      crown(b, accent, gx, gy, w, d, 4.4, 0.6);
      b.add(m.roof, box(gx, h + 0.5, gy, w * 0.9, 1, d * 0.9));
      if (r() < 0.6) antenna(b, m, gx - w * 0.2, h, gy + d * 0.2, 12 + r() * 16);
      else b.add(accent, box(gx, h + 5, gy, w * 0.5, 0.6, d * 0.5));
      anchors.set(node, new THREE.Vector3(gx, h, gy));
      label(h + 20);
      pickBox(pickables, group, m, node, s, h + 8);
      break;
    }
    case "destination": {
      // Remote host: slender amber spire.
      const r = rng(Math.round(gx * 11 + gy * 3));
      b.add(m.facade.warm, facadeBox(gx, 0, gy, w * 0.7, h, d * 0.7, r() * 200));
      b.add(m.trim, box(gx, h + 5, gy, w * 0.5, 10, d * 0.5));
      crown(b, accent, gx, gy, w * 0.7, d * 0.7, h * 0.5, 0.6);
      crown(b, accent, gx, gy, w * 0.7, d * 0.7, h + 0.4, 0.8);
      const spire = new THREE.ConeGeometry(w * 0.2, 36, 4).toNonIndexed();
      spire.rotateY(Math.PI / 4);
      spire.translate(gx, h + 28, gy);
      b.add(accent, spire);
      beam(group, gx, gy, h + 46, 180, 4, s.tint, animated);
      anchors.set(node, new THREE.Vector3(gx, h, gy));
      label(h + 62);
      pickBox(pickables, group, m, node, s, h + 40);
      break;
    }
    default: {
      // "+N more" LAN block.
      for (let i = 0; i < 3; i++) {
        const bh = s.h * (0.6 + i * 0.25);
        b.add(m.facade.cool, facadeBox(gx + (i - 1) * w * 0.3, 0, gy - d * 0.25 + i * d * 0.25, w * 0.3, bh, d * 0.4, i * 60));
        crown(b, accent, gx + (i - 1) * w * 0.3, gy - d * 0.25 + i * d * 0.25, w * 0.3, d * 0.4, bh + 0.4, 0.6);
      }
      anchors.set(node, new THREE.Vector3(gx, s.h, gy));
      label(s.h * 1.2 + 14);
      pickBox(pickables, group, m, node, s, s.h * 1.2);
    }
  }
  void tex;
}

/** Default camera view on the ground: buildings between `target` and the camera stay low. */
export interface GroundView {
  target: THREE.Vector2;
  towardCamera: THREE.Vector2;
}

function capForView(s: BuildingSpec, view: GroundView | null, jitter: number): BuildingSpec {
  if (!view) return s;
  const front = (s.gx - view.target.x) * view.towardCamera.x + (s.gy - view.target.y) * view.towardCamera.y;
  if (front <= 0) return s;
  return { ...s, h: Math.min(s.h, 20 + front * 0.06 + jitter) };
}

export function buildCity(model: SceneModel, tex: CityTextures, env: THREE.Texture | null, view: GroundView | null = null): City {
  const group = new THREE.Group();
  group.name = "city";
  const city: City = { group, pickables: [], animated: [], anchors: new Map(), labels: new Map() };
  const m = makeMats(tex, env);
  const b = new Batches();
  for (const s of model.buildings) {
    if (s.kind === "decor" || !s.node) decor(b, m, tex, capForView(s, view, hash01(Math.round(s.gx), 5) * 14), group, city.animated);
    else landmark(b, m, tex, s, city);
  }
  b.build(group);
  return city;
}

interface Rect {
  x0: number;
  z0: number;
  x1: number;
  z1: number;
}

const FILL_CELL = 120;
const FILL_EXTENT = 1500;
const FILL_TINTS = [0x00e5ff, 0xff2ea6, 0x9b5cff, 0x3d7bff, 0xffb020];

/**
 * Dense background district around the network: generated towers on a street grid with lit
 * corners. Kept clear of every road, plaza and landmark; buildings between the network and the
 * default camera are capped so they never hide the traffic.
 */
export function fillerCity(model: SceneModel, tex: CityTextures, env: THREE.Texture | null, view: GroundView, animated: Animated[]): THREE.Group {
  const { target, towardCamera } = view;
  const group = new THREE.Group();
  group.name = "filler";
  const m = makeMats(tex, env, 12);
  const b = new Batches();
  const blocked: Rect[] = [];
  const pad = (ax: number, az: number, bx: number, bz: number, p: number) =>
    blocked.push({ x0: Math.min(ax, bx) - p, z0: Math.min(az, bz) - p, x1: Math.max(ax, bx) + p, z1: Math.max(az, bz) + p });
  // Highways get a wider corridor: destination towers line them and change with traffic.
  for (const r of model.roads) pad(r.from.x, r.from.y, r.to.x, r.to.y, r.width / 2 + (r.style === "highway" ? 190 : 70));
  for (const p of model.plazas) pad(p.gx - p.w / 2, p.gy - p.d / 2, p.gx + p.w / 2, p.gy + p.d / 2, 60);
  for (const s of model.buildings) pad(s.gx - s.w / 2, s.gy - s.d / 2, s.gx + s.w / 2, s.gy + s.d / 2, s.kind === "decor" ? 22 : 60);
  const hits = (x: number, z: number, h: number) => blocked.some((q) => x + h > q.x0 && x - h < q.x1 && z + h > q.z0 && z - h < q.z1);

  const bounds = new THREE.Box2();
  for (const r of model.roads) bounds.expandByPoint(new THREE.Vector2(r.from.x, r.from.y)).expandByPoint(new THREE.Vector2(r.to.x, r.to.y));
  const c = bounds.getCenter(new THREE.Vector2());
  const r = rng(4242);
  const pools = new THREE.MeshBasicMaterial({
    map: tex.glow,
    color: new THREE.Color(0x7fc8ff).multiplyScalar(0.3),
    blending: THREE.AdditiveBlending,
    transparent: true,
    depthWrite: false,
    toneMapped: false,
  });
  const street = glowMaterial(0x3d7bff, 0.8);
  const x0 = Math.floor((c.x - FILL_EXTENT) / FILL_CELL) * FILL_CELL;
  const z0 = Math.floor((c.y - FILL_EXTENT) / FILL_CELL) * FILL_CELL;
  for (let x = x0; x < c.x + FILL_EXTENT; x += FILL_CELL) {
    for (let z = z0; z < c.y + FILL_EXTENT; z += FILL_CELL) {
      if (!hits(x, z, 6) && r() < 0.7) {
        const q = new THREE.PlaneGeometry(70, 70);
        q.rotateX(-Math.PI / 2);
        q.translate(x, 0.3, z);
        b.add(pools, q.toNonIndexed());
        b.add(street, box(x + FILL_CELL / 2, 0.25, z, FILL_CELL - 60, 0.1, 0.8));
      }
      const cx = x + FILL_CELL / 2 + (r() - 0.5) * 24;
      const cz = z + FILL_CELL / 2 + (r() - 0.5) * 24;
      const size = 44 + r() * 50;
      // Open lots and small plazas break up the grid.
      if (hits(cx, cz, size / 2) || r() < 0.14) continue;
      const front = (cx - target.x) * towardCamera.x + (cz - target.y) * towardCamera.y;
      // Distance to the network's own footprint: blocks right next to it stay low so the core reads.
      const dx = Math.max(bounds.min.x - cx, 0, cx - bounds.max.x);
      const dz = Math.max(bounds.min.y - cz, 0, cz - bounds.max.y);
      const outside = Math.hypot(dx, dz);
      let h = 40 + r() * r() * 300 + Math.min(420, outside * 0.35);
      // The network district itself stays open so its buildings and roads read.
      if (outside < 110) continue;
      if (front > 0) h = Math.min(h, 20 + front * 0.06 + r() * 14);
      const tint = FILL_TINTS[Math.floor(r() * FILL_TINTS.length)]!;
      const w = size * (0.8 + r() * 0.4);
      const d = size * (0.7 + r() * 0.5);
      decor(b, m, tex, { node: null, kind: "decor", gx: cx, gy: cz, w, d, h, tint }, group, animated);
      // Low blocks get neon roof edges so the foreground reads as city, not boxes.
      if (h < 90 && r() < 0.55) crown(b, glow(m, tint, 2.2), cx, cz, w, d, h + 1.2, 0.5);
    }
  }
  b.build(group);
  return group;
}
