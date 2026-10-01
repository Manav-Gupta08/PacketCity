import * as THREE from "three";

import { ARRIVING, FREE, type RoutePool } from "../iso/RoutePool";
import { carModelFor, THREAT_COLOR, THREAT_LABELS, THREAT_MEDIUM_COLOR, VEHICLE_STYLES, type CarModel } from "../vehicleStyles";
import { ROAD_Y } from "./roads";
import { buildCarGeometry, buildCarGeometryLow, carMaterial, glowGeometry, glowMaterialForCars, MODEL_LENGTH, MODEL_WIDTH } from "./vehicles";

const MODELS: CarModel[] = ["coupe", "sedan", "compact", "bike", "interceptor", "van", "hauler"];
/** Beyond this camera distance a car is drawn with its low-poly impostor. */
const LOD_DISTANCE = 460;
/** Heading follows the road with this responsiveness (1/s), so cars turn instead of snapping. */
const TURN_RATE = 9;
const MAX_WIDTH_SCALE = 1.25;
const UNFOCUSED_DIM = 0.16;
/** Hostile cars get a wider, pulsing road glow so they read as an alarm, not just a colour. */
const THREAT_GLOW_SPREAD = 1.5;
const THREAT_PULSE_HZ = 1.6;
/** Half the distance over which road slope is measured for a car's pitch. */
const SLOPE_PROBE = 4;

interface ModelMesh {
  mesh: THREE.InstancedMesh;
  dim: THREE.InstancedBufferAttribute;
  count: number;
}

/** Renders the vehicle pool as instanced futuristic cars plus their road light. */
export class Fleet {
  readonly group = new THREE.Group();
  private readonly models = new Map<string, ModelMesh>();
  private readonly glow: THREE.InstancedMesh;
  private readonly glowDim: THREE.InstancedBufferAttribute;
  private readonly yaw: Float32Array;
  private readonly seen: Float64Array;
  private readonly selection: THREE.Mesh;
  private readonly m4 = new THREE.Matrix4();
  private readonly q = new THREE.Quaternion();
  private readonly p = new THREE.Vector3();
  private readonly s = new THREE.Vector3();
  private readonly up = new THREE.Vector3(0, 1, 0);
  /** Car models point along +x, so nose-up pitch is a rotation about local +z. */
  private readonly forwardNormal = new THREE.Vector3(0, 0, 1);
  private readonly qPitch = new THREE.Quaternion();
  private ground: (x: number, z: number) => number = () => 0;
  private hasRamps = false;
  private readonly colors = new Map<string, THREE.Color>();
  private readonly threatTint = new THREE.Color(THREAT_COLOR);
  private readonly threatGlow = new THREE.Color(THREAT_COLOR);
  private readonly mediumTint = new THREE.Color(THREAT_MEDIUM_COLOR);
  private readonly mediumGlow = new THREE.Color(THREAT_MEDIUM_COLOR);

  constructor(private readonly capacity: number, envMap: THREE.Texture | null) {
    const material = carMaterial(envMap);
    for (const model of MODELS) {
      for (const lod of ["hi", "lo"] as const) {
        const geometry = lod === "hi" ? buildCarGeometry(model) : buildCarGeometryLow(model);
        const mesh = new THREE.InstancedMesh(geometry, material, capacity);
        const dim = new THREE.InstancedBufferAttribute(new Float32Array(capacity), 1);
        dim.setUsage(THREE.DynamicDrawUsage);
        geometry.setAttribute("iDim", dim);
        mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
        mesh.setColorAt(0, new THREE.Color(1, 1, 1));
        mesh.count = 0;
        mesh.frustumCulled = false;
        this.group.add(mesh);
        this.models.set(`${model}:${lod}`, { mesh, dim, count: 0 });
      }
    }
    const gg = glowGeometry();
    this.glowDim = new THREE.InstancedBufferAttribute(new Float32Array(capacity), 1);
    gg.setAttribute("iDim", this.glowDim);
    this.glow = new THREE.InstancedMesh(gg, glowMaterialForCars(), capacity);
    this.glow.setColorAt(0, new THREE.Color(1, 1, 1));
    this.glow.count = 0;
    this.glow.frustumCulled = false;
    this.glow.renderOrder = 2;
    this.group.add(this.glow);
    this.yaw = new Float32Array(capacity);
    this.seen = new Float64Array(capacity);

    const ring = new THREE.RingGeometry(0.9, 1.08, 48);
    ring.rotateX(-Math.PI / 2);
    this.selection = new THREE.Mesh(ring, new THREE.MeshBasicMaterial({ color: new THREE.Color(1, 1, 1).multiplyScalar(3), toneMapped: false, transparent: true, depthWrite: false }));
    this.selection.visible = false;
    this.group.add(this.selection);
  }

  /** Road surface height lookup for the current scene (elevated roads). */
  setGround(ground: (x: number, z: number) => number, hasRamps: boolean): void {
    this.ground = ground;
    this.hasRamps = hasRamps;
  }

  private tint(cls: string, hex: number): THREE.Color {
    let c = this.colors.get(cls);
    if (!c) this.colors.set(cls, (c = new THREE.Color(hex)));
    return c;
  }

  update(pool: RoutePool, dt: number, focusFlowId: number | null, selectedPacketId: number | null, time: number, camera: THREE.Vector3): void {
    for (const m of this.models.values()) m.count = 0;
    let glowN = 0;
    let selected = -1;
    const k = Math.min(1, dt * TURN_RATE);
    const lod2 = LOD_DISTANCE * LOD_DISTANCE;
    const pulse = 0.5 + 0.5 * Math.sin(time * THREAT_PULSE_HZ * Math.PI * 2);
    this.threatGlow.setHex(THREAT_COLOR).multiplyScalar(1.2 + 1.6 * pulse);
    this.mediumGlow.setHex(THREAT_MEDIUM_COLOR).multiplyScalar(1.4);

    for (let i = 0; i < this.capacity; i++) {
      if (pool.state[i] === FREE) continue;
      const ev = pool.events[i];
      if (!ev) continue;
      const len = pool.length[i]!;
      const model = carModelFor(ev.class, ev.packets, len);
      const ddx = pool.gx[i]! - camera.x;
      const ddz = pool.gy[i]! - camera.z;
      const far = ddx * ddx + ddz * ddz + camera.y * camera.y > lod2;
      const mm = this.models.get(far ? `${model}:lo` : `${model}:hi`)!;
      const target = -pool.angle[i]!;
      if (this.seen[i] !== pool.serial[i]) {
        this.seen[i] = pool.serial[i]!;
        this.yaw[i] = target;
      } else {
        let d = target - this.yaw[i]!;
        d = Math.atan2(Math.sin(d), Math.cos(d));
        this.yaw[i] = this.yaw[i]! + d * k;
      }
      const sx = len / MODEL_LENGTH[model];
      const sw = Math.min(sx, MAX_WIDTH_SCALE);
      const gx = pool.gx[i]!;
      const gz = pool.gy[i]!;
      const ground = this.ground(gx, gz);
      this.q.setFromAxisAngle(this.up, this.yaw[i]!);
      if (this.hasRamps) {
        const fx = Math.cos(pool.angle[i]!) * SLOPE_PROBE;
        const fz = Math.sin(pool.angle[i]!) * SLOPE_PROBE;
        const pitch = Math.atan((this.ground(gx + fx, gz + fz) - this.ground(gx - fx, gz - fz)) / (2 * SLOPE_PROBE));
        this.q.multiply(this.qPitch.setFromAxisAngle(this.forwardNormal, pitch));
      }
      // A slight bob sells suspension without costing anything.
      this.p.set(gx, ground + ROAD_Y + Math.sin(time * 6 + i) * 0.08, gz);
      this.s.set(sx, sw, sw);
      this.m4.compose(this.p, this.q, this.s);
      const n = mm.count++;
      mm.mesh.setMatrixAt(n, this.m4);
      const threat = ev.threat != null;
      const high = threat && THREAT_LABELS[ev.threat!].severity === "high";
      const tint = !threat ? this.tint(ev.class, VEHICLE_STYLES[ev.class].color) : high ? this.threatTint : this.mediumTint;
      mm.mesh.setColorAt(n, tint);
      const fade = pool.state[i] === ARRIVING ? pool.alpha[i]! : Math.max(0.15, pool.alpha[i]!);
      const dim = fade * (focusFlowId !== null && ev.flowId !== focusFlowId ? UNFOCUSED_DIM : 1);
      mm.dim.setX(n, dim);

      const spread = threat ? THREAT_GLOW_SPREAD : 1;
      this.s.set(len * (threat ? 1.15 : 1), 1, MODEL_WIDTH[model] * sw * spread);
      this.m4.compose(this.p.setY(ground), this.q, this.s);
      this.glow.setMatrixAt(glowN, this.m4);
      this.glow.setColorAt(glowN, !threat ? tint : high ? this.threatGlow : this.mediumGlow);
      this.glowDim.setX(glowN, dim);
      glowN++;
      if (selectedPacketId !== null && ev.packetId === selectedPacketId) selected = i;
    }

    for (const m of this.models.values()) {
      m.mesh.count = m.count;
      m.mesh.visible = m.count > 0;
      if (m.count === 0) continue;
      m.mesh.instanceMatrix.needsUpdate = true;
      m.mesh.instanceColor!.needsUpdate = true;
      m.dim.needsUpdate = true;
    }
    this.glow.count = glowN;
    this.glow.visible = glowN > 0;
    this.glow.instanceMatrix.needsUpdate = true;
    this.glow.instanceColor!.needsUpdate = true;
    this.glowDim.needsUpdate = true;

    this.selection.visible = selected >= 0;
    if (selected >= 0) {
      const r = pool.length[selected]! * 0.75 + 6;
      this.selection.position.set(pool.gx[selected]!, this.ground(pool.gx[selected]!, pool.gy[selected]!) + ROAD_Y + 0.3, pool.gy[selected]!);
      this.selection.scale.setScalar(r * (1 + 0.06 * Math.sin(time * 6)));
    }
  }

  dispose(): void {
    const materials = new Set<THREE.Material>();
    this.group.traverse((o) => {
      const mesh = o as THREE.Mesh;
      mesh.geometry?.dispose();
      if (mesh.material) materials.add(mesh.material as THREE.Material);
    });
    materials.forEach((m) => m.dispose());
  }
}
