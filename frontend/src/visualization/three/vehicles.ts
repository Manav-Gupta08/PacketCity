import * as THREE from "three";
import { mergeGeometries } from "three/addons/utils/BufferGeometryUtils.js";

import type { CarModel } from "../vehicleStyles";

/**
 * Procedural futuristic cars. Each model is one merged geometry whose vertices carry their part's
 * material (paint / glass / rubber / chrome / light). One patched MeshStandardMaterial renders every
 * part, so a model is a single instanced draw call. Cars face +X; origin at ground centre.
 */

interface PartStyle {
  albedo: number;
  /** 1 = tinted by the protocol colour (body paint). */
  paint: number;
  rough: number;
  metal: number;
  /** Emissive strength; 0 for non-emitting parts. */
  glow: number;
  /** 1 = emissive colour is the protocol colour, 0 = the part's own albedo. */
  glowTint: number;
}

const PAINT: PartStyle = { albedo: 0xffffff, paint: 1, rough: 0.3, metal: 0.35, glow: 0, glowTint: 0 };
const PAINT_DARK: PartStyle = { albedo: 0x55607a, paint: 1, rough: 0.4, metal: 0.6, glow: 0, glowTint: 0 };
const GLASS: PartStyle = { albedo: 0x05070c, paint: 0, rough: 0.06, metal: 0.9, glow: 0, glowTint: 0 };
const RUBBER: PartStyle = { albedo: 0x08090c, paint: 0, rough: 0.85, metal: 0.1, glow: 0, glowTint: 0 };
const CHROME: PartStyle = { albedo: 0x9aa4b8, paint: 0, rough: 0.2, metal: 1, glow: 0, glowTint: 0 };
const TRIM: PartStyle = { albedo: 0x15181f, paint: 0, rough: 0.5, metal: 0.4, glow: 0, glowTint: 0 };
const HEADLIGHT: PartStyle = { albedo: 0xdff4ff, paint: 0, rough: 0.2, metal: 0, glow: 6, glowTint: 0 };
const TAILLIGHT: PartStyle = { albedo: 0xff1a3a, paint: 0, rough: 0.2, metal: 0, glow: 4.5, glowTint: 0 };
const ACCENT: PartStyle = { albedo: 0xffffff, paint: 0, rough: 0.2, metal: 0, glow: 3.2, glowTint: 1 };

function tag(g: THREE.BufferGeometry, s: PartStyle): THREE.BufferGeometry {
  const geo = g.index ? g.toNonIndexed() : g;
  for (const name of Object.keys(geo.attributes)) if (name !== "position" && name !== "normal") geo.deleteAttribute(name);
  if (!geo.getAttribute("normal")) geo.computeVertexNormals();
  const n = geo.getAttribute("position").count;
  const albedo = new Float32Array(n * 3);
  const mat = new Float32Array(n * 4);
  const tint = new Float32Array(n);
  const c = new THREE.Color(s.albedo);
  for (let i = 0; i < n; i++) {
    albedo.set([c.r, c.g, c.b], i * 3);
    mat.set([s.paint, s.rough, s.metal, s.glow], i * 4);
    tint[i] = s.glowTint;
  }
  geo.setAttribute("aAlbedo", new THREE.BufferAttribute(albedo, 3));
  geo.setAttribute("aMat", new THREE.BufferAttribute(mat, 4));
  geo.setAttribute("aGlowTint", new THREE.BufferAttribute(tint, 1));
  return geo;
}

/** Side profile (x = length, y = height) extruded across the car's width, bevelled for soft edges. */
function profile(points: [number, number][], width: number, bevel = 0.35): THREE.BufferGeometry {
  const shape = new THREE.Shape(points.map(([x, y]) => new THREE.Vector2(x, y)));
  const depth = Math.max(0.1, width - bevel * 2);
  const g = new THREE.ExtrudeGeometry(shape, { depth, bevelEnabled: bevel > 0, bevelThickness: bevel, bevelSize: bevel * 0.8, bevelSegments: 2, curveSegments: 4 });
  g.translate(0, 0, -depth / 2);
  return g;
}

function wheel(x: number, z: number, radius: number, width: number, parts: THREE.BufferGeometry[]): void {
  const tyre = new THREE.CylinderGeometry(radius, radius, width, 18);
  tyre.rotateX(Math.PI / 2);
  tyre.translate(x, radius, z);
  parts.push(tag(tyre, RUBBER));
  const side = Math.sign(z);
  const rim = new THREE.CylinderGeometry(radius * 0.62, radius * 0.62, 0.12, 14);
  rim.rotateX(Math.PI / 2);
  rim.translate(x, radius, z + side * (width / 2 + 0.02));
  parts.push(tag(rim, CHROME));
  const ring = new THREE.TorusGeometry(radius * 0.72, 0.14, 5, 18);
  ring.translate(x, radius, z + side * (width / 2 + 0.06));
  parts.push(tag(ring, ACCENT));
}

function boxPart(x: number, y: number, z: number, w: number, h: number, d: number, s: PartStyle): THREE.BufferGeometry {
  const g = new THREE.BoxGeometry(w, h, d);
  g.translate(x, y, z);
  return tag(g, s);
}

interface Spec {
  length: number;
  width: number;
  body: [number, number][];
  cabin: [number, number][];
  /** Glass width relative to body width (>1 shows side windows flush with the body). */
  glassWidth: number;
  wheels: number[];
  wheelRadius: number;
  lightY: number;
  roof?: [number, number][];
  extra?: (parts: THREE.BufferGeometry[], w: number) => void;
}

const SPECS: Record<Exclude<CarModel, "bike" | "hauler">, Spec> = {
  coupe: {
    length: 20,
    width: 8.4,
    body: [[-10, 1.3], [9.8, 1.3], [10.4, 2.4], [9.6, 3.3], [4.2, 3.9], [-6.4, 4.0], [-9.8, 3.7], [-10.4, 2.5]],
    cabin: [[4.4, 3.8], [-0.4, 6.0], [-4.6, 6.0], [-8.6, 3.9]],
    glassWidth: 0.8,
    wheels: [6.4, -6.4],
    wheelRadius: 1.75,
    lightY: 2.7,
    extra: (parts, w) => parts.push(boxPart(-9.8, 4.5, 0, 1.6, 0.35, w * 0.95, PAINT_DARK)),
  },
  sedan: {
    length: 20,
    width: 8.6,
    body: [[-10, 1.3], [10, 1.3], [10.3, 2.7], [9.2, 3.8], [4.6, 4.2], [-6.8, 4.2], [-9.6, 4.0], [-10.3, 2.7]],
    cabin: [[4.9, 4.1], [1.9, 6.7], [-4.8, 6.7], [-7.6, 4.1]],
    glassWidth: 0.86,
    wheels: [6.3, -6.3],
    wheelRadius: 1.8,
    lightY: 2.9,
    roof: [[1.7, 6.62], [-4.6, 6.62], [-4.5, 6.95], [1.5, 6.95]],
  },
  compact: {
    length: 16,
    width: 8,
    body: [[-8, 1.3], [8, 1.3], [8.3, 2.8], [7.1, 4.0], [3.2, 4.4], [-7.4, 4.5], [-8.2, 3.3]],
    cabin: [[3.4, 4.3], [0.8, 7.0], [-6.3, 7.0], [-7.3, 4.4]],
    glassWidth: 0.88,
    wheels: [5.2, -5.3],
    wheelRadius: 1.7,
    lightY: 3.0,
    roof: [[0.6, 6.92], [-6.1, 6.92], [-6.2, 7.3], [0.4, 7.3]],
  },
  interceptor: {
    length: 21,
    width: 8.8,
    body: [[-10.2, 1.1], [10.8, 1.1], [11, 1.8], [4, 3.5], [-8.2, 4.1], [-10.6, 3.1]],
    cabin: [[3.4, 3.4], [-1.0, 5.2], [-5.4, 5.1], [-7.8, 4.0]],
    glassWidth: 0.72,
    wheels: [6.8, -6.6],
    wheelRadius: 1.7,
    lightY: 1.9,
    extra: (parts, w) => {
      parts.push(tag(profile([[-10.2, 4.0], [-8.2, 4.0], [-9.2, 5.6], [-11.2, 5.6]], w * 0.9, 0.15), PAINT_DARK));
      parts.push(boxPart(2.0, 5.35, 0, 1.2, 0.35, w * 0.5, ACCENT));
    },
  },
  van: {
    length: 20,
    width: 9,
    body: [[-10, 1.4], [10, 1.4], [10.3, 3.0], [9.6, 5.3], [7.2, 8.6], [-9.8, 8.8], [-10.3, 3.0]],
    cabin: [[9.3, 5.5], [7.3, 8.3], [2.4, 8.3], [2.4, 5.5]],
    glassWidth: 1.02,
    wheels: [6.4, -6.6],
    wheelRadius: 1.9,
    lightY: 3.2,
    extra: (parts, w) => {
      parts.push(boxPart(-3.8, 6.9, 0, 11, 0.4, w * 1.01, ACCENT));
      parts.push(boxPart(-2, 9.05, 0, 9, 0.5, w * 0.6, TRIM));
    },
  },
};

function buildCar(spec: Spec): THREE.BufferGeometry {
  const w = spec.width;
  const parts: THREE.BufferGeometry[] = [];
  parts.push(tag(profile(spec.body, w), PAINT));
  parts.push(tag(profile(spec.cabin, w * spec.glassWidth, 0.25), GLASS));
  if (spec.roof) parts.push(tag(profile(spec.roof, w * spec.glassWidth * 0.98, 0.1), PAINT));
  parts.push(boxPart(0, 1.05, 0, spec.length * 0.86, 0.5, w * 0.92, TRIM));
  for (const x of spec.wheels) for (const side of [-1, 1]) wheel(x, side * (w / 2 - 0.9), spec.wheelRadius, 1.5, parts);
  const front = Math.max(...spec.body.map(([x]) => x));
  const rear = Math.min(...spec.body.map(([x]) => x));
  for (const side of [-1, 1]) parts.push(boxPart(front + 0.1, spec.lightY, side * (w / 2 - 1.4), 0.5, 0.55, 1.9, HEADLIGHT));
  parts.push(boxPart(front + 0.05, spec.lightY - 0.6, 0, 0.3, 0.18, w * 0.62, ACCENT));
  parts.push(boxPart(rear - 0.05, spec.lightY + 0.5, 0, 0.35, 0.45, w * 0.86, TAILLIGHT));
  for (const side of [-1, 1]) parts.push(boxPart(0, 1.55, side * (w / 2 + 0.02), spec.length * 0.62, 0.22, 0.12, ACCENT));
  spec.extra?.(parts, w);
  return mergeGeometries(parts, false)!;
}

function buildBike(): THREE.BufferGeometry {
  const w = 3.2;
  const parts: THREE.BufferGeometry[] = [];
  parts.push(tag(profile([[-8.4, 2.4], [8.6, 2.4], [9.4, 3.4], [6.2, 5.0], [-1.6, 4.6], [-7.2, 5.2], [-9.2, 3.8]], w, 0.5), PAINT));
  parts.push(tag(profile([[6.2, 4.9], [3.6, 6.8], [2.4, 6.6], [4.4, 4.6]], w * 0.8, 0.15), GLASS));
  parts.push(tag(profile([[-1.2, 4.6], [-6.4, 4.8], [-6.0, 5.6], [-1.6, 5.4]], w * 0.9, 0.2), TRIM));
  for (const x of [6.4, -6.2]) {
    const tyre = new THREE.TorusGeometry(2.1, 0.75, 8, 22);
    tyre.translate(x, 2.2, 0);
    parts.push(tag(tyre, RUBBER));
    const ring = new THREE.TorusGeometry(1.5, 0.16, 5, 22);
    for (const side of [-1, 1]) {
      const r = ring.clone();
      r.translate(x, 2.2, side * 0.8);
      parts.push(tag(r, ACCENT));
    }
  }
  parts.push(boxPart(9.2, 3.6, 0, 0.5, 0.6, 1.6, HEADLIGHT));
  parts.push(boxPart(-9.2, 4.4, 0, 0.35, 0.4, 1.8, TAILLIGHT));
  for (const side of [-1, 1]) parts.push(boxPart(1, 2.6, side * (w / 2 + 0.02), 10, 0.2, 0.1, ACCENT));
  return mergeGeometries(parts, false)!;
}

function buildHauler(): THREE.BufferGeometry {
  const w = 9.4;
  const parts: THREE.BufferGeometry[] = [];
  // Cab.
  parts.push(tag(profile([[11, 1.4], [20, 1.4], [20.3, 3.2], [19.6, 8.2], [17.4, 10.2], [11, 10.2]], w), PAINT));
  parts.push(tag(profile([[19.6, 5.4], [18.9, 8.4], [15.2, 9.4], [15.2, 5.4]], w * 1.02, 0.1), GLASS));
  parts.push(boxPart(15, 10.5, 0, 6, 0.6, w * 0.8, TRIM));
  for (const side of [-1, 1]) parts.push(boxPart(20.35, 3.4, side * (w / 2 - 1.5), 0.5, 0.7, 2.2, HEADLIGHT));
  parts.push(boxPart(20.3, 2.4, 0, 0.3, 0.2, w * 0.7, ACCENT));
  // Data container trailer.
  parts.push(boxPart(-4.6, 6.3, 0, 30, 9, w, PAINT_DARK));
  for (const side of [-1, 1]) {
    parts.push(boxPart(-4.6, 8.8, side * (w / 2 + 0.03), 28, 0.35, 0.1, ACCENT));
    parts.push(boxPart(-4.6, 3.6, side * (w / 2 + 0.03), 28, 0.2, 0.1, ACCENT));
    for (let k = 0; k < 6; k++) parts.push(boxPart(-17 + k * 5, 6.2, side * (w / 2 + 0.02), 0.25, 3.8, 0.08, TRIM));
  }
  parts.push(boxPart(-19.7, 7.2, 0, 0.35, 0.6, w * 0.9, TAILLIGHT));
  parts.push(boxPart(-4.6, 1.2, 0, 30, 0.6, w * 0.8, TRIM));
  for (const x of [17, 7.6, -11, -15.2]) for (const side of [-1, 1]) wheel(x, side * (w / 2 - 1), 1.9, 1.6, parts);
  return mergeGeometries(parts, false)!;
}

/** Design length of each model; instances are scaled so this matches the vehicle's length. */
export const MODEL_LENGTH: Record<CarModel, number> = {
  coupe: 20.8,
  sedan: 20.6,
  compact: 16.5,
  interceptor: 21.8,
  van: 20.6,
  bike: 18.6,
  hauler: 40,
};

export const MODEL_WIDTH: Record<CarModel, number> = {
  coupe: 8.4,
  sedan: 8.6,
  compact: 8,
  interceptor: 8.8,
  van: 9,
  bike: 3.2,
  hauler: 9.4,
};

export function buildCarGeometry(model: CarModel): THREE.BufferGeometry {
  if (model === "bike") return buildBike();
  if (model === "hauler") return buildHauler();
  return buildCar(SPECS[model]);
}

/**
 * Distant-car impostor (~100 triangles): same proportions, paint, glass, dark wheel band and the
 * light bars that read at range. Swapped in beyond the LOD distance.
 */
export function buildCarGeometryLow(model: CarModel): THREE.BufferGeometry {
  const L = MODEL_LENGTH[model];
  const W = MODEL_WIDTH[model];
  const parts: THREE.BufferGeometry[] = [];
  if (model === "hauler") {
    parts.push(boxPart(15.5, 5.6, 0, 9, 8.4, W, PAINT));
    parts.push(boxPart(19.4, 6.8, 0, 1.4, 3, W * 1.02, GLASS));
    parts.push(boxPart(-4.6, 6.3, 0, 30, 9, W, PAINT_DARK));
    parts.push(boxPart(-4.6, 8.8, 0, 28, 0.35, W + 0.2, ACCENT));
    parts.push(boxPart(-19.9, 7.2, 0, 0.3, 0.6, W * 0.9, TAILLIGHT));
    parts.push(boxPart(20.3, 3.4, 0, 0.4, 0.7, W * 0.8, HEADLIGHT));
    parts.push(boxPart(0, 1.6, 0, L * 0.95, 2.6, W * 1.02, RUBBER));
    return mergeGeometries(parts, false)!;
  }
  const tall = model === "van";
  const bike = model === "bike";
  const bodyH = tall ? 7.2 : bike ? 2.6 : 3.0;
  const bodyY = bike ? 2.4 : 1.3;
  parts.push(boxPart(0, bodyY + bodyH / 2, 0, L * 0.98, bodyH, W, PAINT));
  if (tall) {
    parts.push(boxPart(L * 0.3, 6.6, 0, L * 0.3, 2.6, W * 1.02, GLASS));
  } else {
    const cabinL = bike ? L * 0.2 : L * 0.45;
    const cabinH = bike ? 1.6 : 2.4;
    parts.push(boxPart(bike ? L * 0.2 : -L * 0.08, bodyY + bodyH + cabinH / 2, 0, cabinL, cabinH, W * (bike ? 0.7 : 0.82), GLASS));
  }
  parts.push(boxPart(0, bike ? 1.8 : 1.4, 0, L * 0.8, bike ? 3.6 : 2.8, W * (bike ? 0.6 : 1.04), RUBBER));
  parts.push(boxPart(L * 0.495, bodyY + bodyH * 0.45, 0, 0.4, 0.6, W * 0.8, HEADLIGHT));
  parts.push(boxPart(-L * 0.495, bodyY + bodyH * 0.7, 0, 0.4, 0.5, W * 0.86, TAILLIGHT));
  parts.push(boxPart(0, bodyY + 0.3, 0, L * 0.62, 0.22, W + 0.1, ACCENT));
  return mergeGeometries(parts, false)!;
}

/**
 * MeshStandardMaterial patched to read albedo/roughness/metalness/emission per vertex, tint paint
 * and accents with the instance colour, and dim per instance (`iDim`: fade-in, focus mode).
 */
export function carMaterial(envMap: THREE.Texture | null): THREE.MeshStandardMaterial {
  const m = new THREE.MeshStandardMaterial({ color: 0xffffff, envMap, envMapIntensity: 0.75 });
  m.onBeforeCompile = (shader) => {
    shader.vertexShader = shader.vertexShader
      .replace(
        "#include <common>",
        `#include <common>
attribute vec3 aAlbedo; attribute vec4 aMat; attribute float aGlowTint; attribute float iDim;
varying vec3 vAlbedo; varying vec4 vMat; varying float vGlowTint; varying float vDim; varying vec3 vTint;`,
      )
      .replace(
        "#include <begin_vertex>",
        `#include <begin_vertex>
vAlbedo = aAlbedo; vMat = aMat; vGlowTint = aGlowTint; vDim = iDim;
#ifdef USE_INSTANCING_COLOR
vTint = instanceColor;
#else
vTint = vec3(1.0);
#endif`,
      );
    shader.fragmentShader = shader.fragmentShader
      .replace(
        "#include <common>",
        `#include <common>
varying vec3 vAlbedo; varying vec4 vMat; varying float vGlowTint; varying float vDim; varying vec3 vTint;`,
      )
      .replace("#include <color_fragment>", "diffuseColor.rgb = mix(vAlbedo, vAlbedo * vTint, vMat.x) * vDim;")
      .replace("#include <roughnessmap_fragment>", "float roughnessFactor = vMat.y;")
      .replace("#include <metalnessmap_fragment>", "float metalnessFactor = vMat.z;")
      .replace(
        "#include <emissivemap_fragment>",
        "#include <emissivemap_fragment>\ntotalEmissiveRadiance = mix(vAlbedo, vTint, vGlowTint) * vMat.w * vDim;",
      );
  };
  return m;
}

/**
 * Additive light on the road per car: underglow in the protocol colour, a headlight wash ahead
 * and a taillight smear behind (reads as reflections on wet asphalt). One quad set per car.
 */
export function glowGeometry(): THREE.BufferGeometry {
  const quads: [number, number, number, number, number][] = [
    // part, centre x, length, width, (unused)
    [0, 0, 1.35, 2.4, 0],
    [1, 1.15, 1.5, 1.5, 0],
    [2, -0.95, 0.9, 1.0, 0],
  ];
  const geos = quads.map(([part, cx, len, wid]) => {
    const g = new THREE.PlaneGeometry(len, wid);
    g.rotateX(-Math.PI / 2);
    g.translate(cx, 0.35 + part * 0.02, 0);
    const n = g.getAttribute("position").count;
    g.setAttribute("aPart", new THREE.BufferAttribute(new Float32Array(n).fill(part), 1));
    return g.toNonIndexed();
  });
  return mergeGeometries(geos, false)!;
}

export function glowMaterialForCars(): THREE.ShaderMaterial {
  return new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    toneMapped: false,
    vertexShader: `
attribute float aPart; attribute float iDim;
varying vec2 vUv; varying float vPart; varying float vDim; varying vec3 vTint;
void main() {
  vUv = uv; vPart = aPart; vDim = iDim;
#ifdef USE_INSTANCING_COLOR
  vTint = instanceColor;
#else
  vTint = vec3(1.0);
#endif
  gl_Position = projectionMatrix * modelViewMatrix * instanceMatrix * vec4(position, 1.0);
}`,
    fragmentShader: `
varying vec2 vUv; varying float vPart; varying float vDim; varying vec3 vTint;
void main() {
  vec2 p = vUv * 2.0 - 1.0;
  vec3 c; float a;
  if (vPart < 0.5) {
    a = pow(max(0.0, 1.0 - dot(p, p)), 1.4) * 0.9; c = vTint;
  } else if (vPart < 1.5) {
    float along = vUv.x; float across = 1.0 - abs(p.y);
    a = pow(1.0 - along, 1.6) * pow(max(0.0, across), 2.2) * 0.22; c = vec3(0.7, 0.85, 1.0);
  } else {
    float along = vUv.x; float across = 1.0 - abs(p.y);
    a = pow(along, 2.0) * pow(max(0.0, across), 3.0) * 0.55; c = vec3(1.0, 0.12, 0.2);
  }
  gl_FragColor = vec4(c * a * vDim, 1.0);
}`,
  });
}
