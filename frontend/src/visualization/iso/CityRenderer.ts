import * as THREE from "three";
import { MapControls } from "three/addons/controls/MapControls.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";

import type { TrafficEvent } from "../../types";
import { trafficBus } from "../../services/trafficBus";
import { ConvoyStaging } from "../staging";
import { buildCity, fillerCity, posKey, type City, type GroundView } from "../three/buildings";
import { FOG_COLOR, FOG_DENSITY, lighting, neonEnvironment, Rain, skyDome, skyline } from "../three/environment";
import { Fleet } from "../three/fleet";
import { disposeTree } from "../three/geom";
import { buildRoads, ROAD_Y } from "../three/roads";
import { adTexture, arrowTexture, asphaltTexture, facadeTextures, glowTexture, groundTexture, wetnessTexture, type Facade, type FacadePalette } from "../three/textures";
import { vehicleLength, vehicleSpeed } from "../vehicleStyles";
import { buildRoute, type Route } from "./routes";
import { FREE, RoutePool } from "./RoutePool";
import { groundHeightFn, type Scene, type SignSpec } from "./scene";

const POOL_CAPACITY = 1200;
/** Max events moved from the IPC bus into staging per frame. */
const INTAKE_PER_FRAME = 400;
/** Max new vehicles per frame; keeps on-ramps readable. */
const SPAWN_BUDGET_PER_FRAME = 30;
const STAGING_MAX_KEYS = 768;
/** Ground-unit clearance between vehicles in a lane; excess traffic merges into convoys. */
const MIN_GAP = 18;
const METRICS_INTERVAL_MS = 500;
/** Pointer travel (px) below which a press counts as a click rather than a drag. */
const CLICK_SLOP = 5;
const FOV = 50;
const MAX_PIXEL_RATIO = 1;
/** Small labels are hidden beyond this camera distance unless selected. */
const SMALL_LABEL_MAX_DIST = 1500;
const LABEL_REF_DIST = 750;
const QUALITY_TARGET_FPS = 40;
/** Consecutive slow metric samples (0.5 s each) before lowering quality. */
const QUALITY_SLOW_SAMPLES = 6;

export interface HoverInfo {
  event: TrafficEvent;
  x: number;
  y: number;
}

export interface CityMetrics {
  fps: number;
  vehicles: number;
  waiting: number;
  mergedPackets: number;
  filteredPackets: number;
  offMapPackets: number;
}

export interface CityCallbacks {
  onHover(info: HoverInfo | null): void;
  onSelectVehicle(event: TrafficEvent): void;
  onSelectNode(node: string): void;
  onMetrics(m: CityMetrics): void;
}

interface Pose {
  position: THREE.Vector3;
  target: THREE.Vector3;
}

interface SharedTextures {
  facades: Record<FacadePalette, Facade>;
  ads: THREE.Texture[];
  glow: THREE.Texture;
  asphalt: THREE.Texture;
  wetness: THREE.Texture;
  arrow: THREE.Texture;
  ground: THREE.Texture;
}

/**
 * Cinematic 3D city. Traffic logic (bus → convoy staging → lanes → vehicle pool) is unchanged
 * from the data side; this class turns the scene layout into roads, buildings and instanced cars,
 * and renders them with fog, bloom and neon reflections.
 */
export class CityRenderer {
  private readonly pool = new RoutePool(POOL_CAPACITY, { accelDistance: 70, brakeDistance: 90, minFactor: 0.35 });
  private readonly staging = new ConvoyStaging(STAGING_MAX_KEYS);
  private scene: Scene | null = null;
  private ground: (x: number, y: number) => number = () => 0;
  /** Route per lane id; lane ids are stable across scene rebuilds, routes are not. */
  private readonly laneRoutes = new Map<number, Route>();
  private readonly laneIds = new Map<string, number>();

  private renderer: THREE.WebGLRenderer | null = null;
  private composer: EffectComposer | null = null;
  private controls: MapControls | null = null;
  private readonly world = new THREE.Scene();
  private readonly camera = new THREE.PerspectiveCamera(FOV, 1, 5, 20000);
  private env: THREE.Texture | null = null;
  private tex: SharedTextures | null = null;
  private fleet: Fleet | null = null;
  private rain: Rain | null = null;
  private staticGroup: THREE.Group | null = null;
  /** Filler district, skyline and ground: expensive, and only depend on the road layout. */
  private background: { key: string; group: THREE.Group } | null = null;
  private city: City | null = null;
  private nodeRing: THREE.Mesh | null = null;
  private host: HTMLElement | null = null;
  private signLayer: HTMLElement | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private defaultPose: Pose | null = null;
  private readonly clock = new THREE.Clock();
  private readonly raycaster = new THREE.Raycaster();
  private readonly v = new THREE.Vector3();

  private filter: (e: TrafficEvent) => boolean = () => true;
  private paused = false;
  private focusFlowId: number | null = null;
  private selectedPacketId: number | null = null;
  private selectedNode: string | null = null;
  private packetsPerSec = 0;

  private userCamera = false;
  private pointer: { x: number; y: number } | null = null;
  private press: { x: number; y: number } | null = null;
  private hovered = -1;
  private signEls = new Map<string, HTMLElement>();
  private signPos = new Map<string, THREE.Vector3>();

  private filteredPackets = 0;
  private offMapPackets = 0;
  private qualityLevel = 0;
  private slowSamples = 0;
  private frames = 0;
  private frameNo = 0;
  private lastMetrics = performance.now();
  private destroyed = false;
  private active = true;

  constructor(private readonly cb: CityCallbacks) {}

  async init(host: HTMLElement, signLayer: HTMLElement | null): Promise<void> {
    if (this.destroyed) return;
    this.host = host;
    this.signLayer = signLayer;
    const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 0.95;
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    this.renderer = renderer;
    host.appendChild(renderer.domElement);

    this.env = neonEnvironment(renderer);
    this.tex = {
      facades: { warm: facadeTextures("warm", 1), cool: facadeTextures("cool", 2), neon: facadeTextures("neon", 3) },
      ads: Array.from({ length: 6 }, (_, i) => adTexture(i)),
      glow: glowTexture(),
      asphalt: asphaltTexture(),
      wetness: wetnessTexture(),
      arrow: arrowTexture(),
      ground: groundTexture(),
    };
    this.world.fog = new THREE.FogExp2(FOG_COLOR, FOG_DENSITY);
    this.world.add(skyDome());
    this.world.add(lighting());
    this.fleet = new Fleet(POOL_CAPACITY, this.env);
    this.world.add(this.fleet.group);
    this.rain = new Rain();
    this.world.add(this.rain.mesh);
    const ring = new THREE.RingGeometry(0.92, 1, 64);
    ring.rotateX(-Math.PI / 2);
    this.nodeRing = new THREE.Mesh(ring, new THREE.MeshBasicMaterial({ color: new THREE.Color(1, 1, 1).multiplyScalar(2.5), toneMapped: false, transparent: true, depthWrite: false }));
    this.nodeRing.visible = false;
    this.world.add(this.nodeRing);

    const controls = new MapControls(this.camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.screenSpacePanning = false;
    controls.maxPolarAngle = 1.38;
    controls.minPolarAngle = 0.15;
    controls.minDistance = 60;
    controls.maxDistance = 4200;
    controls.zoomToCursor = true;
    controls.addEventListener("start", () => (this.userCamera = true));
    this.controls = controls;

    const composer = new EffectComposer(renderer);
    composer.addPass(new RenderPass(this.world, this.camera));
    composer.addPass(new UnrealBloomPass(new THREE.Vector2(512, 512), 0.55, 0.45, 0.9));
    composer.addPass(new OutputPass());
    this.composer = composer;

    const canvas = renderer.domElement;
    canvas.addEventListener("pointerdown", this.onPointerDown);
    canvas.addEventListener("pointermove", this.onPointerMove);
    canvas.addEventListener("pointerup", this.onPointerUp);
    canvas.addEventListener("pointerleave", this.onPointerLeave);
    this.resizeObserver = new ResizeObserver(() => this.resize());
    this.resizeObserver.observe(host);
    this.resize();
    if (this.scene) this.buildStatic();
    if (this.active) renderer.setAnimationLoop(this.frame);
  }

  // --- public controls -----------------------------------------------------------------------

  /** `resetTraffic` clears vehicles (switching views); device-list refreshes keep them moving. */
  setScene(scene: Scene, resetTraffic: boolean): void {
    this.scene = scene;
    this.laneRoutes.clear();
    if (resetTraffic) {
      this.reset();
      this.userCamera = false;
    }
    if (this.renderer) this.buildStatic();
  }

  setFilter(filter: (e: TrafficEvent) => boolean): void {
    this.filter = filter;
    this.pool.dismiss(filter);
    this.staging.clear();
  }

  setPaused(paused: boolean): void {
    if (this.paused && !paused) this.staging.clear();
    this.paused = paused;
  }

  /** Stops rendering entirely while the view is hidden. */
  setActive(active: boolean): void {
    this.active = active;
    this.renderer?.setAnimationLoop(active ? this.frame : null);
  }

  setFocusFlow(flowId: number | null): void {
    this.focusFlowId = flowId;
  }

  setSelectedPacket(packetId: number | null): void {
    this.selectedPacketId = packetId;
  }

  setSelectedNode(node: string | null): void {
    this.selectedNode = node;
    this.placeNodeRing();
  }

  setTraffic(packetsPerSec: number): void {
    this.packetsPerSec = packetsPerSec;
  }

  reset(): void {
    this.pool.clear();
    this.staging.clear();
    this.filteredPackets = 0;
    this.offMapPackets = 0;
  }

  /** Returns to the cinematic default view. */
  fit(): void {
    this.userCamera = false;
    this.applyPose();
  }

  zoomBy(factor: number): void {
    const c = this.controls;
    if (!c) return;
    const offset = this.camera.position.clone().sub(c.target);
    const dist = THREE.MathUtils.clamp(offset.length() / factor, c.minDistance, c.maxDistance);
    this.camera.position.copy(c.target).add(offset.setLength(dist));
    this.userCamera = true;
    c.update();
  }

  /** Dev automation: place the camera explicitly (world units). */
  debugCamera(position: [number, number, number], target: [number, number, number]): void {
    this.userCamera = true;
    this.camera.position.set(...position);
    this.controls?.target.set(...target);
    this.controls?.update();
  }

  destroy(): void {
    this.destroyed = true;
    const r = this.renderer;
    if (!r) return;
    r.setAnimationLoop(null);
    const canvas = r.domElement;
    canvas.removeEventListener("pointerdown", this.onPointerDown);
    canvas.removeEventListener("pointermove", this.onPointerMove);
    canvas.removeEventListener("pointerup", this.onPointerUp);
    canvas.removeEventListener("pointerleave", this.onPointerLeave);
    this.resizeObserver?.disconnect();
    this.controls?.dispose();
    this.fleet?.dispose();
    this.rain?.dispose();
    disposeTree(this.world);
    if (this.tex) {
      const t = this.tex;
      for (const f of Object.values(t.facades)) {
        f.map.dispose();
        f.emissive.dispose();
      }
      [...t.ads, t.glow, t.asphalt, t.wetness, t.arrow, t.ground].forEach((x) => x.dispose());
    }
    this.env?.dispose();
    this.composer?.dispose();
    r.dispose();
    canvas.remove();
  }

  // --- static scene -----------------------------------------------------------------------------

  private buildStatic(): void {
    const scene = this.scene!;
    const tex = this.tex!;
    if (this.staticGroup) {
      this.world.remove(this.staticGroup);
      disposeTree(this.staticGroup);
    }
    const group = new THREE.Group();
    group.name = "static";

    const bounds = new THREE.Box2();
    for (const r of scene.model.roads) bounds.expandByPoint(new THREE.Vector2(r.from.x, r.from.y)).expandByPoint(new THREE.Vector2(r.to.x, r.to.y));
    for (const b of scene.model.buildings) {
      bounds.expandByPoint(new THREE.Vector2(b.gx - b.w / 2, b.gy - b.d / 2)).expandByPoint(new THREE.Vector2(b.gx + b.w / 2, b.gy + b.d / 2));
    }
    const center = bounds.getCenter(new THREE.Vector2());
    const size = bounds.getSize(new THREE.Vector2());
    this.defaultPose = this.poseFor(scene, center, size);
    const pose = this.defaultPose;
    const view: GroundView = {
      target: new THREE.Vector2(pose.target.x, pose.target.z),
      towardCamera: new THREE.Vector2(pose.position.x - pose.target.x, pose.position.z - pose.target.z).normalize(),
    };

    const city = buildCity(scene.model, tex, this.env, view);
    this.city = city;
    group.add(city.group);
    group.add(buildRoads(scene.model, tex, this.env));
    this.ground = groundHeightFn(scene.model.roads);
    this.fleet?.setGround(this.ground, scene.model.roads.some((r) => r.elevation));

    // Destination towers come and go with traffic; the background ignores them (the highway
    // corridor is kept clear instead) so it survives those rebuilds.
    const layout = {
      ...scene.model,
      buildings: scene.model.buildings.filter((b) => b.kind !== "destination" && b.kind !== "decor"),
    };
    const bgKey = [
      scene.kind,
      ...layout.roads.map((r) => `${r.from.x},${r.from.y},${r.to.x},${r.to.y},${r.width}`),
      ...layout.buildings.map((b) => `${Math.round(b.gx)},${Math.round(b.gy)},${b.w},${b.d}`),
    ].join("|");
    if (this.background?.key !== bgKey) {
      if (this.background) {
        this.world.remove(this.background.group);
        disposeTree(this.background.group);
      }
      const bg = new THREE.Group();
      bg.name = "background";
      const groundMat = new THREE.MeshStandardMaterial({ map: tex.ground, roughness: 0.62, metalness: 0.3, envMap: this.env, envMapIntensity: 0.5 });
      tex.ground.repeat.set(30, 30);
      const ground = new THREE.Mesh(new THREE.PlaneGeometry(12000, 12000), groundMat);
      ground.rotation.x = -Math.PI / 2;
      ground.position.set(center.x, 0, center.y);
      bg.add(ground);
      const f = tex.facades;
      bg.add(skyline(center, Math.max(size.x, size.y) * 0.8 + 1400, [f.cool, f.neon, f.warm]));
      const fillerAnimated: { update(t: number): void }[] = [];
      bg.add(fillerCity(layout, tex, this.env, view, fillerAnimated));
      bg.userData.animated = fillerAnimated;
      this.background = { key: bgKey, group: bg };
      this.world.add(bg);
    }
    city.animated.push(...(this.background.group.userData.animated as { update(t: number): void }[]));

    this.staticGroup = group;
    this.world.add(group);
    this.signPos.clear();
    this.signEls.clear();
    this.placeNodeRing();
    if (!this.userCamera) this.applyPose();
  }

  private placeNodeRing(): void {
    const ring = this.nodeRing;
    if (!ring) return;
    const b = this.selectedNode ? this.scene?.model.buildings.find((x) => x.node === this.selectedNode && x.kind !== "destination") : undefined;
    ring.visible = !!b;
    if (!b) return;
    ring.position.set(b.gx, ROAD_Y + 0.4, b.gy);
    ring.scale.setScalar(Math.max(b.w, b.d) * 0.85);
  }

  // --- camera -------------------------------------------------------------------------------

  private poseFor(scene: Scene, center: THREE.Vector2, size: THREE.Vector2): Pose {
    const model = scene.model;
    if (scene.kind === "personal") {
      const self = model.buildings.find((b) => b.node === "self");
      const inet = model.buildings.find((b) => b.node === "internet" && b.kind === "internet");
      const sx = self?.gx ?? 0;
      const sz = self?.gy ?? 600;
      const iz = inet?.gy ?? -600;
      // Elevated three-quarter view from the outgoing side: YOUR DEVICE at the near end, both
      // carriageways receding toward the internet gate in the haze.
      return {
        position: new THREE.Vector3(sx + 640, 300, sz - 110),
        target: new THREE.Vector3(sx - 90, 0, sz + (iz - sz) * 0.53),
      };
    }
    const key = model.buildings.filter((b) => b.kind !== "decor");
    const box = new THREE.Box2();
    for (const b of key) box.expandByPoint(new THREE.Vector2(b.gx, b.gy));
    const c = box.isEmpty() ? center : box.getCenter(new THREE.Vector2());
    void size;
    // Everything the establishing shot must show: YOUR DEVICE, router, internet gate, the far end
    // of the LAN avenue and the broadcast plaza.
    const must: THREE.Vector3[] = [];
    for (const node of ["self", "gateway", "internet"]) {
      const b = model.buildings.find((x) => x.node === node && x.kind !== "destination");
      if (b) must.push(new THREE.Vector3(b.gx, b.h + 40, b.gy));
    }
    const lan = model.buildings.filter((b) => b.kind === "device" || b.kind === "overflow");
    const farLan = lan.reduce<(typeof lan)[number] | null>((m, b) => (!m || b.gx > m.gx ? b : m), null);
    if (farLan) must.push(new THREE.Vector3(farLan.gx, farLan.h + 30, farLan.gy));
    const plaza = model.plazas.find((p) => !p.ring);
    if (plaza) must.push(new THREE.Vector3(plaza.gx, 0, plaza.gy));
    return this.searchPose(must, c) ?? this.orbitPose(new THREE.Vector3(c.x, 0, c.y - 150), 15, 24, 1400);
  }

  private orbitPose(target: THREE.Vector3, azimuthDeg: number, elevationDeg: number, dist: number): Pose {
    const az = THREE.MathUtils.degToRad(azimuthDeg);
    const el = THREE.MathUtils.degToRad(elevationDeg);
    const position = new THREE.Vector3(
      target.x + Math.cos(el) * Math.sin(az) * dist,
      Math.sin(el) * dist,
      target.z + Math.cos(el) * Math.cos(az) * dist,
    );
    return { position, target };
  }

  /**
   * Low cinematic shot that keeps every key landmark on screen (clear of the legend on the left
   * and the chart strip at the bottom), preferring the pose where they spread out the most.
   */
  private searchPose(points: THREE.Vector3[], c: THREE.Vector2): Pose | null {
    if (points.length === 0) return null;
    const cam = this.camera.clone();
    let best: Pose | null = null;
    let bestScore = -Infinity;
    for (const az of [0, 12, 24, 36])
      for (const el of [20, 24, 28])
        for (const dist of [1000, 1200, 1450, 1750, 2100])
          for (const dx of [-250, -100, 50])
            for (const dz of [-300, -150, 0]) {
              const pose = this.orbitPose(new THREE.Vector3(c.x + dx, 0, c.y + dz), az, el, dist);
              cam.position.copy(pose.position);
              cam.lookAt(pose.target);
              cam.updateMatrixWorld();
              let ok = true;
              let x0 = 9, x1 = -9, y0 = 9, y1 = -9;
              for (const p of points) {
                this.v.copy(p).project(cam);
                if (this.v.z > 1 || this.v.x < -0.6 || this.v.x > 0.9 || this.v.y < -0.72 || this.v.y > 0.8) {
                  ok = false;
                  break;
                }
                x0 = Math.min(x0, this.v.x);
                x1 = Math.max(x1, this.v.x);
                y0 = Math.min(y0, this.v.y);
                y1 = Math.max(y1, this.v.y);
              }
              // Spread on screen, with a mild preference for lower, closer shots.
              const score = ok ? (x1 - x0) * (y1 - y0) - el * 0.004 - dist * 0.00005 : -Infinity;
              if (score > bestScore) {
                bestScore = score;
                best = pose;
              }
            }
    return best;
  }

  private applyPose(): void {
    const p = this.defaultPose;
    if (!p || !this.controls) return;
    this.camera.position.copy(p.position);
    this.controls.target.copy(p.target);
    this.controls.update();
  }

  private resize(): void {
    const host = this.host;
    const r = this.renderer;
    if (!host || !r) return;
    const w = Math.max(2, host.clientWidth);
    const h = Math.max(2, host.clientHeight);
    r.setSize(w, h);
    this.composer?.setSize(w, h);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    if (this.scene && !this.userCamera && this.staticGroup) {
      const bounds = new THREE.Box2();
      for (const b of this.scene.model.buildings) bounds.expandByPoint(new THREE.Vector2(b.gx, b.gy));
      this.defaultPose = this.poseFor(this.scene, bounds.getCenter(new THREE.Vector2()), bounds.getSize(new THREE.Vector2()));
      this.applyPose();
    }
  }

  // --- frame loop -----------------------------------------------------------------------------

  private frame = (): void => {
    const dt = Math.min(this.clock.getDelta(), 0.1);
    const t = this.clock.elapsedTime;
    if (!this.paused && this.scene) {
      this.intake();
      this.staging.drain(this.trySpawn, SPAWN_BUDGET_PER_FRAME);
      this.pool.update(dt);
    }
    this.controls?.update();
    this.fleet?.update(this.pool, dt, this.focusFlowId, this.selectedPacketId, t, this.camera.position);
    if (this.city) for (const a of this.city.animated) a.update(t);
    this.rain?.update(t, this.v.copy(this.camera.position).lerp(this.controls?.target ?? this.v, 0.35));
    if (this.nodeRing?.visible) (this.nodeRing.material as THREE.MeshBasicMaterial).opacity = 0.65 + 0.35 * Math.sin(t * 4);
    this.composer?.render(dt);
    this.updateSigns();
    if (this.pointer && !this.press) this.updateHover();
    this.reportMetrics();
  };

  private laneId(key: string): number {
    let id = this.laneIds.get(key);
    if (id === undefined) {
      id = this.laneIds.size + 1;
      this.laneIds.set(key, id);
    }
    return id;
  }

  private intake(): void {
    for (let n = 0; n < INTAKE_PER_FRAME; n++) {
      const ev = trafficBus.shift();
      if (!ev) break;
      if (!this.filter(ev)) {
        this.filteredPackets += ev.packets;
        continue;
      }
      const lane = this.laneFor(ev);
      if (lane === null) {
        this.offMapPackets += ev.packets;
        continue;
      }
      this.staging.add(ev, lane);
    }
  }

  /** Resolves (and caches) the lane an event drives in; null if it has no place in the scene. */
  private laneFor(ev: TrafficEvent): number | null {
    const req = this.scene!.route(ev);
    if (!req) return null;
    const lane = this.laneId(req.key);
    if (!this.laneRoutes.has(lane)) this.laneRoutes.set(lane, buildRoute(req.points, req.offset));
    return lane;
  }

  private trySpawn = (ev: TrafficEvent, lane: number): boolean => {
    if (this.pool.isFull) return false;
    const length = vehicleLength(ev.bytes);
    if (!this.pool.entranceClear(lane, length, MIN_GAP)) return false;
    // After a scene rebuild the lane's route is re-derived on demand.
    const route = this.laneRoutes.get(lane) ?? (this.laneFor(ev) !== null ? this.laneRoutes.get(lane) : undefined);
    if (!route || route.length <= 0) return true;
    this.pool.spawn({ route, laneKey: lane, length, speed: vehicleSpeed(ev.class, ev.bytes, this.packetsPerSec), event: ev });
    return true;
  };

  // --- holographic labels ---------------------------------------------------------------------

  private labelPoint(s: SignSpec): THREE.Vector3 {
    let p = this.signPos.get(s.id);
    if (p) return p;
    const city = this.city;
    const unique = s.id === "self" || s.id === "router" || s.id === "internet";
    const anchorNode = s.id === "router" ? "gateway" : s.node;
    const building = unique && anchorNode ? this.scene?.model.buildings.find((b) => b.node === anchorNode && b.kind !== "destination") : undefined;
    p =
      (building && city?.labels.get(posKey(building.gx, building.gy))) ??
      city?.labels.get(posKey(s.gx, s.gy)) ??
      new THREE.Vector3(s.gx, s.z, s.gy);
    this.signPos.set(s.id, p);
    return p;
  }

  private updateSigns(): void {
    const layer = this.signLayer;
    const scene = this.scene;
    if (!layer || !scene || !this.host) return;
    const signs = scene.model.signs;
    if (this.signEls.size !== signs.length || this.frameNo++ % 30 === 0) {
      this.signEls.clear();
      layer.querySelectorAll<HTMLElement>("[data-sign]").forEach((el) => this.signEls.set(el.dataset.sign!, el));
    }
    const w = this.host.clientWidth;
    const h = this.host.clientHeight;
    for (const s of signs) {
      const el = this.signEls.get(s.id);
      if (!el) continue;
      const p = this.labelPoint(s);
      const dist = this.camera.position.distanceTo(p);
      this.v.copy(p).project(this.camera);
      const selected = !!s.node && s.node === this.selectedNode && s.size === "sm";
      const onScreen = this.v.z < 1 && Math.abs(this.v.x) < 1.15 && Math.abs(this.v.y) < 1.2;
      const visible = onScreen && (s.size !== "sm" || dist < SMALL_LABEL_MAX_DIST || selected);
      if (!visible) {
        if (el.style.display !== "none") el.style.display = "none";
        continue;
      }
      if (el.style.display === "none") el.style.display = "";
      const x = (this.v.x * 0.5 + 0.5) * w;
      const y = (-this.v.y * 0.5 + 0.5) * h;
      const base = s.size === "lg" ? 1 : s.size === "md" ? 0.95 : 0.9;
      const scale = THREE.MathUtils.clamp((LABEL_REF_DIST / dist) * base, 0.5, 1.05);
      el.style.transform = `translate3d(${x.toFixed(1)}px, ${y.toFixed(1)}px, 0) scale(${scale.toFixed(3)}) translate(-50%, calc(-100% - var(--stem)))`;
      el.style.zIndex = String(Math.round(20000 - dist));
    }
  }

  // --- interaction ----------------------------------------------------------------------------

  /** Screen-space pick: nearest car whose on-screen footprint contains the pointer. */
  private hitVehicle(sx: number, sy: number): number {
    const host = this.host;
    if (!host) return -1;
    const w = host.clientWidth;
    const h = host.clientHeight;
    const p = this.pool;
    const focal = h / (2 * Math.tan(THREE.MathUtils.degToRad(FOV) / 2));
    let best = -1;
    let bestScore = Infinity;
    for (let i = 0; i < POOL_CAPACITY; i++) {
      if (p.state[i] === FREE) continue;
      this.v.set(p.gx[i]!, this.ground(p.gx[i]!, p.gy[i]!) + ROAD_Y + 3, p.gy[i]!);
      const dist = this.camera.position.distanceTo(this.v);
      this.v.project(this.camera);
      if (this.v.z > 1) continue;
      const x = (this.v.x * 0.5 + 0.5) * w;
      const y = (-this.v.y * 0.5 + 0.5) * h;
      const radius = Math.max(8, (p.length[i]! * 0.6 * focal) / dist);
      const d = Math.hypot(x - sx, y - sy);
      if (d > radius) continue;
      const score = d / radius + dist * 1e-5;
      if (score < bestScore) {
        bestScore = score;
        best = i;
      }
    }
    return best;
  }

  private hitBuilding(sx: number, sy: number): string | null {
    const host = this.host;
    if (!host || !this.city) return null;
    const ndc = new THREE.Vector2((sx / host.clientWidth) * 2 - 1, -(sy / host.clientHeight) * 2 + 1);
    this.raycaster.setFromCamera(ndc, this.camera);
    const hit = this.raycaster.intersectObjects(this.city.pickables, false)[0];
    return (hit?.object.userData.node as string | undefined) ?? null;
  }

  private onPointerDown = (e: PointerEvent): void => {
    this.press = { x: e.offsetX, y: e.offsetY };
  };

  private onPointerMove = (e: PointerEvent): void => {
    this.pointer = { x: e.offsetX, y: e.offsetY };
  };

  private onPointerUp = (e: PointerEvent): void => {
    const press = this.press;
    this.press = null;
    if (!press || Math.hypot(e.offsetX - press.x, e.offsetY - press.y) > CLICK_SLOP || e.button !== 0) return;
    const i = this.hitVehicle(e.offsetX, e.offsetY);
    const ev = i >= 0 ? this.pool.events[i] : null;
    if (ev) {
      this.cb.onSelectVehicle(ev);
      return;
    }
    const node = this.hitBuilding(e.offsetX, e.offsetY);
    if (node) this.cb.onSelectNode(node);
  };

  private onPointerLeave = (): void => {
    this.pointer = null;
    this.press = null;
    this.hovered = -1;
    this.cb.onHover(null);
  };

  private updateHover(): void {
    const pt = this.pointer!;
    const canvas = this.renderer!.domElement;
    const i = this.hitVehicle(pt.x, pt.y);
    const ev = i >= 0 ? this.pool.events[i] : null;
    if (i === this.hovered && ev) return;
    this.hovered = i;
    this.cb.onHover(ev ? { event: ev, x: pt.x, y: pt.y } : null);
    const overNode = !ev && this.frameNo % 3 === 0 && this.hitBuilding(pt.x, pt.y);
    canvas.style.cursor = ev || overNode ? "pointer" : "";
  }

  private reportMetrics(): void {
    this.frames++;
    const now = performance.now();
    const elapsed = now - this.lastMetrics;
    if (elapsed < METRICS_INTERVAL_MS) return;
    const fps = (this.frames * 1000) / elapsed;
    this.adaptQuality(fps);
    this.cb.onMetrics({
      fps,
      vehicles: this.pool.active,
      waiting: this.staging.size + trafficBus.length,
      mergedPackets: this.staging.merged,
      filteredPackets: this.filteredPackets,
      offMapPackets: this.offMapPackets,
    });
    this.frames = 0;
    this.lastMetrics = now;
  }

  /**
   * Keeps weak GPUs smooth: after ~3 s below target, drop rain, then bloom. Never re-enabled
   * automatically within a session, so quality doesn't oscillate.
   */
  private adaptQuality(fps: number): void {
    if (this.qualityLevel >= 2 || this.frameNo < 120) return;
    this.slowSamples = fps < QUALITY_TARGET_FPS ? this.slowSamples + 1 : 0;
    if (this.slowSamples < QUALITY_SLOW_SAMPLES) return;
    this.slowSamples = 0;
    this.qualityLevel++;
    if (this.qualityLevel === 1 && this.rain) this.rain.mesh.visible = false;
    if (this.qualityLevel === 2 && this.composer) this.composer.passes[1]!.enabled = false;
  }
}
