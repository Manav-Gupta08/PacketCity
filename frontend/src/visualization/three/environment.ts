import * as THREE from "three";

import { Batches, facadeBox } from "./geom";
import { rng, type Facade } from "./textures";

export const FOG_COLOR = 0x221640;
export const FOG_DENSITY = 0.00042;

/** Night sky: deep navy zenith, violet light-pollution haze at the horizon. Ignores fog. */
export function skyDome(): THREE.Mesh {
  const mat = new THREE.ShaderMaterial({
    side: THREE.BackSide,
    depthWrite: false,
    fog: false,
    uniforms: {
      uZenith: { value: new THREE.Color(0x03050d) },
      uMid: { value: new THREE.Color(0x0c1030) },
      uHorizon: { value: new THREE.Color(0x3a1a52) },
      uGlow: { value: new THREE.Color(0x0e4a7a) },
    },
    vertexShader: "varying vec3 vDir; void main(){ vDir = normalize(position); gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }",
    fragmentShader: `uniform vec3 uZenith; uniform vec3 uMid; uniform vec3 uHorizon; uniform vec3 uGlow; varying vec3 vDir;
void main(){
  float h = clamp(vDir.y, -0.2, 1.0);
  vec3 c = mix(uHorizon, uMid, smoothstep(0.0, 0.22, h));
  c = mix(c, uZenith, smoothstep(0.22, 0.75, h));
  c += uGlow * exp(-abs(h) * 14.0) * 0.6;
  gl_FragColor = vec4(c, 1.0);
}`,
  });
  const mesh = new THREE.Mesh(new THREE.SphereGeometry(9000, 32, 16), mat);
  mesh.renderOrder = -10;
  mesh.frustumCulled = false;
  return mesh;
}

/**
 * Environment for reflections: a dark room lined with neon tubes and a warm window wall, so car
 * paint, glass and wet asphalt pick up cyan/magenta highlights instead of a studio light.
 */
export function neonEnvironment(renderer: THREE.WebGLRenderer): THREE.Texture {
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x05060c);
  const room = new THREE.Mesh(new THREE.BoxGeometry(100, 50, 100), new THREE.MeshBasicMaterial({ color: 0x0a0c18, side: THREE.BackSide }));
  scene.add(room);
  const tube = (color: number, intensity: number, w: number, h: number, x: number, y: number, z: number, ry: number) => {
    const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ color: new THREE.Color(color).multiplyScalar(intensity), side: THREE.DoubleSide }));
    m.position.set(x, y, z);
    m.rotation.y = ry;
    scene.add(m);
  };
  tube(0x00e5ff, 6, 60, 2, 0, 18, -49, 0);
  tube(0xff2ea6, 6, 60, 2, 0, 10, 49, Math.PI);
  tube(0x7a5cff, 4, 70, 3, -49, 14, 0, Math.PI / 2);
  tube(0xffc27a, 2.2, 40, 16, 49, 8, 10, -Math.PI / 2);
  tube(0x3d7bff, 3, 90, 1.5, 0, 24, 0, 0);
  const sky = new THREE.Mesh(new THREE.PlaneGeometry(100, 100), new THREE.MeshBasicMaterial({ color: new THREE.Color(0x1a2450).multiplyScalar(1.4) }));
  sky.rotation.x = Math.PI / 2;
  sky.position.y = 24.9;
  scene.add(sky);
  const pmrem = new THREE.PMREMGenerator(renderer);
  const env = pmrem.fromScene(scene, 0.02).texture;
  pmrem.dispose();
  scene.traverse((o) => {
    const mesh = o as THREE.Mesh;
    mesh.geometry?.dispose();
    (mesh.material as THREE.Material | undefined)?.dispose();
  });
  return env;
}

/** Moonlight, magenta rim and cyan fill: the city stays dark but its forms read. */
export function lighting(): THREE.Group {
  const group = new THREE.Group();
  group.add(new THREE.HemisphereLight(0x5a6ac0, 0x201030, 1.1));
  const moon = new THREE.DirectionalLight(0xa8b8ff, 1.1);
  moon.position.set(-600, 900, -300);
  group.add(moon);
  const rim = new THREE.DirectionalLight(0xff4fb8, 0.7);
  rim.position.set(700, 300, -900);
  group.add(rim);
  const fill = new THREE.DirectionalLight(0x2ad4ff, 0.45);
  fill.position.set(400, 250, 900);
  group.add(fill);
  return group;
}

/** Distant skyline ring: unlit towers (lit windows only) fading into the haze; one draw call per palette. */
export function skyline(center: THREE.Vector2, inner: number, facades: Facade[]): THREE.Group {
  const group = new THREE.Group();
  const mats = facades.map((f) => new THREE.MeshBasicMaterial({ map: f.emissive, color: new THREE.Color(0.85, 0.85, 0.95) }));
  const b = new Batches();
  const r = rng(2024);
  for (let i = 0; i < 380; i++) {
    const a = r() * Math.PI * 2;
    const dist = inner + r() * 2600;
    const x = center.x + Math.cos(a) * dist;
    const z = center.y + Math.sin(a) * dist;
    const w = 60 + r() * 120;
    const h = 160 + Math.pow(r(), 1.6) * 1100;
    b.add(mats[i % mats.length]!, facadeBox(x, 0, z, w, h, w * (0.7 + r() * 0.6), r() * 500));
  }
  b.build(group);
  return group;
}

/** Falling rain streaks around a moving centre; animated in the vertex shader. */
export class Rain {
  readonly mesh: THREE.LineSegments;
  private readonly mat: THREE.ShaderMaterial;

  constructor(count = 900, radius = 650, height = 600) {
    const pos = new Float32Array(count * 6);
    const drop = new Float32Array(count * 4);
    const r = rng(5);
    for (let i = 0; i < count; i++) {
      const x = (r() - 0.5) * radius * 2;
      const z = (r() - 0.5) * radius * 2;
      const y = r() * height;
      const s = r();
      // Both ends of a streak share its base height so wrapping never stretches a streak.
      pos.set([x, 0, z, x + 1.2, -18, z + 0.6], i * 6);
      drop.set([y, s, y, s], i * 4);
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    g.setAttribute("aDrop", new THREE.BufferAttribute(drop, 2));
    this.mat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: { uTime: { value: 0 }, uHeight: { value: height }, uCenter: { value: new THREE.Vector3() } },
      vertexShader: `uniform float uTime; uniform float uHeight; uniform vec3 uCenter; attribute vec2 aDrop; varying float vA;
void main(){
  vec3 p = position;
  p.y += mod(aDrop.x - uTime * (520.0 + aDrop.y * 180.0), uHeight) + 18.0;
  p.xz += uCenter.xz;
  vA = 0.05 + aDrop.y * 0.07;
  vec4 mv = modelViewMatrix * vec4(p, 1.0);
  // Streaks right in front of the lens would smear across the screen.
  vA *= smoothstep(90.0, 260.0, -mv.z);
  gl_Position = projectionMatrix * mv;
}`,
      fragmentShader: "varying float vA; void main(){ gl_FragColor = vec4(vec3(0.55, 0.7, 1.0) * vA, 1.0); }",
    });
    this.mesh = new THREE.LineSegments(g, this.mat);
    this.mesh.frustumCulled = false;
  }

  update(t: number, center: THREE.Vector3): void {
    this.mat.uniforms.uTime!.value = t;
    this.mat.uniforms.uCenter!.value.copy(center);
  }

  dispose(): void {
    this.mesh.geometry.dispose();
    this.mat.dispose();
  }
}
