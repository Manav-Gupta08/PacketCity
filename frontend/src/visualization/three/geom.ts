import * as THREE from "three";
import { mergeGeometries } from "three/addons/utils/BufferGeometryUtils.js";

import { FACADE_TILE_H, FACADE_TILE_W } from "./textures";

const tmpMatrix = new THREE.Matrix4();

/**
 * Axis-aligned box whose UVs are world-space facade coordinates (u = distance along the face,
 * v = height), so one tiling window texture fits every building without stretching. Tops map to
 * texel (0,0), which the facade textures keep dark.
 */
export function facadeBox(cx: number, y0: number, cz: number, w: number, h: number, d: number, uOffset = 0): THREE.BufferGeometry {
  const g = new THREE.BoxGeometry(w, h, d).toNonIndexed();
  g.translate(cx, y0 + h / 2, cz);
  const pos = g.getAttribute("position") as THREE.BufferAttribute;
  const nor = g.getAttribute("normal") as THREE.BufferAttribute;
  const uv = g.getAttribute("uv") as THREE.BufferAttribute;
  for (let i = 0; i < pos.count; i++) {
    const nx = nor.getX(i);
    const ny = nor.getY(i);
    if (Math.abs(ny) > 0.5) {
      uv.setXY(i, 0.001, 0.001);
      continue;
    }
    const along = Math.abs(nx) > 0.5 ? pos.getZ(i) * -Math.sign(nx) : pos.getX(i) * Math.sign(nor.getZ(i));
    uv.setXY(i, (along + uOffset) / FACADE_TILE_W, (pos.getY(i) - y0) / FACADE_TILE_H);
  }
  return g;
}

/** Plain box (no meaningful UVs), non-indexed so it merges with everything else. */
export function box(cx: number, cy: number, cz: number, w: number, h: number, d: number, rotY = 0): THREE.BufferGeometry {
  const g = new THREE.BoxGeometry(w, h, d);
  if (rotY) g.rotateY(rotY);
  g.translate(cx, cy, cz);
  return g.toNonIndexed();
}

/**
 * Box oriented along a ground direction: `length` along (ux, uz), `width` across it.
 * UVs are replaced with world XZ / `uvScale` so tiling textures line up across segments.
 */
export function groundBox(
  cx: number,
  cz: number,
  ux: number,
  uz: number,
  length: number,
  width: number,
  y0: number,
  height: number,
  uvScale = 0,
  segments = 1,
): THREE.BufferGeometry {
  const g = new THREE.BoxGeometry(length, height, width, segments);
  const angle = Math.atan2(-uz, ux);
  tmpMatrix.makeRotationY(angle).setPosition(cx, y0 + height / 2, cz);
  g.applyMatrix4(tmpMatrix);
  const out = g.toNonIndexed();
  if (uvScale > 0) worldUV(out, uvScale);
  return out;
}

/** Flat quad lying on the ground (facing up), oriented along (ux, uz). */
export function groundQuad(cx: number, y: number, cz: number, ux: number, uz: number, length: number, width: number, segments = 1): THREE.BufferGeometry {
  const g = new THREE.PlaneGeometry(length, width, segments);
  g.rotateX(-Math.PI / 2);
  g.rotateY(Math.atan2(-uz, ux));
  g.translate(cx, y, cz);
  return g.toNonIndexed();
}

export function worldUV(g: THREE.BufferGeometry, scale: number): void {
  const pos = g.getAttribute("position") as THREE.BufferAttribute;
  const uv = new Float32Array(pos.count * 2);
  for (let i = 0; i < pos.count; i++) {
    uv[i * 2] = pos.getX(i) / scale;
    uv[i * 2 + 1] = pos.getZ(i) / scale;
  }
  g.setAttribute("uv", new THREE.BufferAttribute(uv, 2));
}

/** Drops attributes a batch doesn't use so geometries from different generators merge. */
function normalise(g: THREE.BufferGeometry, keepUV: boolean): THREE.BufferGeometry {
  const out = g.index ? g.toNonIndexed() : g;
  for (const name of Object.keys(out.attributes)) {
    if (name !== "position" && name !== "normal" && !(keepUV && name === "uv")) out.deleteAttribute(name);
  }
  if (keepUV && !out.getAttribute("uv")) {
    out.setAttribute("uv", new THREE.BufferAttribute(new Float32Array((out.getAttribute("position").count) * 2), 2));
  }
  if (!out.getAttribute("normal")) out.computeVertexNormals();
  return out;
}

/** Collects geometry per material and emits one merged mesh per material (few draw calls). */
export class Batches {
  private readonly parts = new Map<THREE.Material, THREE.BufferGeometry[]>();

  add(material: THREE.Material, geometry: THREE.BufferGeometry): void {
    let list = this.parts.get(material);
    if (!list) this.parts.set(material, (list = []));
    list.push(geometry);
  }

  build(target: THREE.Object3D, renderOrder = 0): void {
    for (const [material, list] of this.parts) {
      if (list.length === 0) continue;
      const keepUV = "map" in material && !!(material as THREE.MeshStandardMaterial).map
        || "emissiveMap" in material && !!(material as THREE.MeshStandardMaterial).emissiveMap
        || material instanceof THREE.ShaderMaterial;
      const merged = mergeGeometries(list.map((g) => normalise(g, keepUV)), false);
      for (const g of list) g.dispose();
      if (!merged) continue;
      merged.computeBoundingSphere();
      const mesh = new THREE.Mesh(merged, material);
      mesh.renderOrder = renderOrder;
      mesh.matrixAutoUpdate = false;
      target.add(mesh);
    }
    this.parts.clear();
  }
}

/** Unlit emissive colour that feeds bloom: intensity > 1 pushes it past the bloom threshold. */
export function glowMaterial(color: number, intensity: number, opts: { additive?: boolean; opacity?: number } = {}): THREE.MeshBasicMaterial {
  const m = new THREE.MeshBasicMaterial({ color: new THREE.Color(color).multiplyScalar(intensity), toneMapped: false, fog: true });
  if (opts.additive) {
    m.blending = THREE.AdditiveBlending;
    m.transparent = true;
    m.depthWrite = false;
  }
  if (opts.opacity !== undefined) {
    m.transparent = true;
    m.opacity = opts.opacity;
  }
  return m;
}

/** Recursively frees GPU resources of everything under `root`. */
export function disposeTree(root: THREE.Object3D): void {
  const materials = new Set<THREE.Material>();
  root.traverse((o) => {
    const mesh = o as THREE.Mesh;
    if (mesh.geometry) mesh.geometry.dispose();
    const m = mesh.material;
    if (Array.isArray(m)) m.forEach((x) => materials.add(x));
    else if (m) materials.add(m);
  });
  for (const m of materials) m.dispose();
}
