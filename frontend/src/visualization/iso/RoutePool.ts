import type { TrafficEvent } from "../../types";
import { Heading } from "./projection";
import { sampleRoute, type Route, type RouteSample } from "./routes";

/** Vehicle lifecycle: spawn → travel (fade in on the on-ramp) → arrive → fade out → free. */
export const FREE = 0;
export const TRAVELING = 1;
export const ARRIVING = 2;

/** Ground distance over which a new vehicle fades in. */
const FADE_IN_DISTANCE = 24;
const FADE_OUT_SECONDS = 0.35;
/** Bumper-to-bumper clearance kept behind the vehicle ahead in the same lane. */
export const FOLLOW_GAP = 8;

export interface SpawnSpec {
  route: Route;
  /** Vehicles sharing a lane key queue behind each other at the on-ramp. */
  laneKey: number;
  length: number;
  /** Ground units per second. */
  speed: number;
  event: TrafficEvent;
}

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Speed profile: vehicles pull away from their origin and brake into their destination. */
export interface Easing {
  /** Distance over which a vehicle accelerates from `minFactor` to cruising speed. */
  accelDistance: number;
  /** Distance before the route end over which it slows to `minFactor`. */
  brakeDistance: number;
  minFactor: number;
}

const NO_EASING: Easing = { accelDistance: 0, brakeDistance: 0, minFactor: 1 };

/**
 * Fixed-capacity, struct-of-arrays vehicle store for route-following vehicles. No per-frame
 * allocation; positions are sampled into typed arrays the renderer reads directly.
 */
export class RoutePool {
  readonly state: Uint8Array;
  readonly dist: Float32Array;
  readonly speed: Float32Array;
  readonly length: Float32Array;
  readonly alpha: Float32Array;
  readonly gx: Float32Array;
  readonly gy: Float32Array;
  readonly heading: Uint8Array;
  readonly angle: Float32Array;
  readonly serial: Float64Array;
  /** Vehicle ahead in the same lane (-1 if none) and its serial, to detect slot reuse. */
  readonly leader: Int32Array;
  private readonly leaderSerial: Float64Array;
  readonly events: (TrafficEvent | null)[];
  readonly routes: (Route | null)[];
  private readonly freeList: Int32Array;
  private freeCount: number;
  private readonly tails = new Map<number, number>();
  private readonly sample: RouteSample = { x: 0, y: 0, heading: Heading.PosX, angle: 0 };
  private nextSerial = 1;
  active = 0;
  /** Spawn attempts rejected because every slot was in use. */
  overflow = 0;

  constructor(
    readonly capacity: number,
    private readonly easing: Easing = NO_EASING,
  ) {
    this.state = new Uint8Array(capacity);
    this.dist = new Float32Array(capacity);
    this.speed = new Float32Array(capacity);
    this.length = new Float32Array(capacity);
    this.alpha = new Float32Array(capacity);
    this.gx = new Float32Array(capacity);
    this.gy = new Float32Array(capacity);
    this.heading = new Uint8Array(capacity);
    this.angle = new Float32Array(capacity);
    this.serial = new Float64Array(capacity);
    this.leader = new Int32Array(capacity).fill(-1);
    this.leaderSerial = new Float64Array(capacity);
    this.events = new Array(capacity).fill(null);
    this.routes = new Array(capacity).fill(null);
    this.freeList = new Int32Array(capacity);
    for (let i = 0; i < capacity; i++) this.freeList[i] = capacity - 1 - i;
    this.freeCount = capacity;
  }

  get isFull(): boolean {
    return this.freeCount === 0;
  }

  /** True if a vehicle of `newLength` can enter keeping `gap` clearance behind the lane's last entrant. */
  entranceClear(laneKey: number, newLength: number, gap: number): boolean {
    const tail = this.tails.get(laneKey);
    if (tail === undefined || this.state[tail] === FREE) return true;
    return this.dist[tail]! >= (this.length[tail]! + newLength) / 2 + gap;
  }

  spawn(spec: SpawnSpec): number {
    if (this.freeCount === 0) {
      this.overflow++;
      return -1;
    }
    const i = this.freeList[--this.freeCount]!;
    const tail = this.tails.get(spec.laneKey);
    const follows = tail !== undefined && this.state[tail] === TRAVELING && this.routes[tail] === spec.route;
    this.leader[i] = follows ? tail : -1;
    this.leaderSerial[i] = follows ? this.serial[tail]! : 0;
    this.state[i] = TRAVELING;
    this.dist[i] = 0;
    this.speed[i] = spec.speed;
    this.length[i] = spec.length;
    this.alpha[i] = 0;
    this.serial[i] = this.nextSerial++;
    this.events[i] = spec.event;
    this.routes[i] = spec.route;
    this.tails.set(spec.laneKey, i);
    this.place(i);
    this.active++;
    return i;
  }

  private place(i: number): void {
    const s = sampleRoute(this.routes[i]!, this.dist[i]!, this.sample);
    this.gx[i] = s.x;
    this.gy[i] = s.y;
    this.heading[i] = s.heading;
    this.angle[i] = s.angle;
  }

  private speedFactor(i: number): number {
    const { accelDistance, brakeDistance, minFactor } = this.easing;
    const d = this.dist[i]!;
    const remaining = this.routes[i]!.length - d;
    let f = 1;
    if (accelDistance > 0 && d < accelDistance) f = Math.min(f, minFactor + (1 - minFactor) * (d / accelDistance));
    if (brakeDistance > 0 && remaining < brakeDistance) f = Math.min(f, minFactor + (1 - minFactor) * (remaining / brakeDistance));
    return f;
  }

  release(i: number): void {
    if (this.state[i] === FREE) return;
    this.state[i] = FREE;
    this.events[i] = null;
    this.routes[i] = null;
    this.freeList[this.freeCount++] = i;
    this.active--;
  }

  update(dt: number): void {
    for (let i = 0; i < this.capacity; i++) {
      const s = this.state[i];
      if (s === FREE) continue;
      if (s === TRAVELING) {
        let d = this.dist[i]! + this.speed[i]! * this.speedFactor(i) * dt;
        const l = this.leader[i]!;
        if (l >= 0) {
          if (this.state[l] === TRAVELING && this.serial[l] === this.leaderSerial[i]) {
            // Car-following: slow down behind a slower vehicle, never reverse.
            const limit = this.dist[l]! - (this.length[l]! + this.length[i]!) / 2 - FOLLOW_GAP;
            if (d > limit) d = Math.max(this.dist[i]!, limit);
          } else {
            this.leader[i] = -1;
          }
        }
        this.dist[i] = d;
        this.alpha[i] = Math.min(1, d / FADE_IN_DISTANCE);
        this.place(i);
        if (d >= this.routes[i]!.length) this.state[i] = ARRIVING;
      } else {
        const a = this.alpha[i]! - dt / FADE_OUT_SECONDS;
        this.alpha[i] = a;
        if (a <= 0) this.release(i);
      }
    }
  }

  /** Starts the fade-out for vehicles the predicate rejects (e.g. after a filter change). */
  dismiss(keep: (event: TrafficEvent) => boolean): void {
    for (let i = 0; i < this.capacity; i++) {
      const ev = this.events[i];
      if (this.state[i] === TRAVELING && ev && !keep(ev)) this.state[i] = ARRIVING;
    }
  }

  clear(): void {
    for (let i = 0; i < this.capacity; i++) this.release(i);
    this.tails.clear();
  }

  hitTest(x: number, y: number, bounds: (i: number) => Rect, tolerance = 4): number {
    let best = -1;
    for (let i = 0; i < this.capacity; i++) {
      if (this.state[i] === FREE) continue;
      const r = bounds(i);
      const inside =
        x >= r.x - tolerance && x <= r.x + r.w + tolerance && y >= r.y - tolerance && y <= r.y + r.h + tolerance;
      if (inside && (best < 0 || this.serial[i]! > this.serial[best]!)) best = i;
    }
    return best;
  }
}
