import { describe, expect, it } from "vitest";

import type { DeviceSnapshot, TrafficEvent } from "../types";
import { stickyDestinations, type Destination } from "./destinations";
import { compileFilter, parseFilter } from "./filter";
import { project, unproject, type Heading } from "./iso/projection";
import { buildRoute, joinPaths, sampleRoute, type RouteSample } from "./iso/routes";
import { ARRIVING, FOLLOW_GAP, FREE, RoutePool, TRAVELING } from "./iso/RoutePool";
import { groundHeightFn, laneFor, profileHeight } from "./iso/scene";
import { carriagewayFor } from "./lanes";
import { buildGlobalScene, MAX_DEVICE_BUILDINGS } from "./scenes/globalScene";
import { buildPersonalScene } from "./scenes/personalScene";
import { MAX_VEHICLE_LENGTH, MIN_VEHICLE_LENGTH, THREAT_COLOR, THREAT_MEDIUM_COLOR, threatColor, VEHICLE_STYLES, vehicleLength, vehicleSpeed } from "./vehicleStyles";

function ev(over: Partial<TrafficEvent> = {}): TrafficEvent {
  return {
    packetId: 1,
    flowId: 7,
    timestampUs: 0,
    direction: "outgoing",
    cast: "unicast",
    class: "https",
    transport: "tcp",
    srcNode: "self",
    dstNode: "internet",
    src: "192.168.1.20",
    dst: "142.250.1.1",
    srcPort: 52431,
    dstPort: 443,
    host: "www.example.com",
    length: 1200,
    packets: 1,
    bytes: 1200,
    threat: null,
    ...over,
  };
}

function device(node: string, role: DeviceSnapshot["role"], bytes = 1000): DeviceSnapshot {
  return {
    node,
    role,
    label: node,
    hostname: null,
    hostnameSource: null,
    vendor: null,
    mac: null,
    ips: [],
    packetsSent: 1,
    packetsReceived: 1,
    bytesSent: bytes,
    bytesReceived: 0,
    firstSeenUs: 0,
    lastSeenUs: 0,
  };
}

describe("visualization filter", () => {
  const match = (f: string, e: TrafficEvent) => compileFilter(parseFilter(f))(e);

  it("selects hostile traffic with threat / malicious", () => {
    const bad = ev({ threat: "backdoorPort" });
    expect(match("threat", bad)).toBe(true);
    expect(match("malicious", ev())).toBe(false);
    expect(match("!threat", bad)).toBe(false);
    expect(match("threat tcp", bad)).toBe(true);
  });

  it("matches everything when empty", () => {
    expect(match("", ev())).toBe(true);
  });

  it("treats tcp as transport so HTTPS over TCP matches", () => {
    expect(match("tcp", ev())).toBe(true);
    expect(match("udp", ev())).toBe(false);
    expect(match("icmp", ev({ transport: "icmpv6", class: "icmp" }))).toBe(true);
  });

  it("ORs same-key terms and ANDs different keys", () => {
    expect(match("dns https port:443", ev())).toBe(true);
    expect(match("dns https port:53", ev())).toBe(false);
  });

  it("supports ip wildcards, host substrings, direction and negation", () => {
    expect(match("ip:192.168.*", ev())).toBe(true);
    expect(match("ip:10.0.0.1", ev())).toBe(false);
    expect(match("host:example", ev())).toBe(true);
    expect(match("direction:in", ev())).toBe(false);
    expect(match("direction:outgoing !port:443", ev())).toBe(false);
    expect(match("-dns", ev())).toBe(true);
    expect(match("flow:7", ev())).toBe(true);
    expect(match("!class:https", ev())).toBe(false);
    expect(match("!class:tcp", ev())).toBe(true);
  });

  it("reports invalid terms without throwing", () => {
    const parsed = parseFilter("port:99999 banana direction:sideways");
    expect(parsed.errors).toHaveLength(3);
    expect(parsed.terms).toHaveLength(0);
  });
});

describe("protocol, direction and size mapping", () => {
  it("assigns every class a distinct colour", () => {
    const colours = Object.values(VEHICLE_STYLES).map((s) => s.color);
    expect(new Set(colours).size).toBe(colours.length);
  });

  it("maps directions to carriageways", () => {
    expect(carriagewayFor("incoming")).toBe("incoming");
    expect(carriagewayFor("local")).toBe("outgoing");
    expect(carriagewayFor("transit")).toBeNull();
  });

  it("keeps a flow in a stable lane and spreads flows across lanes", () => {
    expect(laneFor(42, 1, 3)).toBe(laneFor(42, 999, 3));
    expect(new Set(Array.from({ length: 30 }, (_, i) => laneFor(i, 0, 3))).size).toBe(3);
  });

  it("scales length with bytes within bounds and speed with class/size/rate", () => {
    expect(vehicleLength(60)).toBe(MIN_VEHICLE_LENGTH);
    expect(vehicleLength(1500)).toBeGreaterThan(vehicleLength(100));
    expect(vehicleLength(10_000_000)).toBe(MAX_VEHICLE_LENGTH);
    expect(vehicleSpeed("dns", 80, 10)).toBeGreaterThan(vehicleSpeed("tcp", 80, 10));
    expect(vehicleSpeed("tcp", 1500, 10)).toBeLessThan(vehicleSpeed("tcp", 60, 10));
    expect(vehicleSpeed("tcp", 60, 5000)).toBeGreaterThan(vehicleSpeed("tcp", 60, 1));
  });
});

describe("isometric geometry", () => {
  it("projects and unprojects the ground plane", () => {
    const s = project(120, -40);
    const g = unproject(s.x, s.y);
    expect(g.x).toBeCloseTo(120);
    expect(g.y).toBeCloseTo(-40);
  });

  it("offsets routes to the right of travel with mitered corners", () => {
    const r = buildRoute([{ x: 0, y: 0 }, { x: 100, y: 0 }, { x: 100, y: 100 }], 10);
    expect([r.xs[0], r.ys[0]]).toEqual([0, 10]);
    expect(r.xs[1]).toBeCloseTo(90);
    expect(r.ys[1]).toBeCloseTo(10);
    expect([r.xs[2], r.ys[2]]).toEqual([90, 100]);
    expect(r.length).toBeCloseTo(180);
    const out: RouteSample = { x: 0, y: 0, heading: 0 as Heading, angle: 0 };
    sampleRoute(r, 135, out);
    expect(out.x).toBeCloseTo(90);
    expect(out.y).toBeCloseTo(55);
    expect(out.heading).toBe(1);
    expect(out.angle).toBeCloseTo(Math.PI / 2);
  });

  it("puts opposite directions on the same road on opposite sides", () => {
    const a = buildRoute([{ x: 0, y: 0 }, { x: 100, y: 0 }], 10);
    const b = buildRoute([{ x: 100, y: 0 }, { x: 0, y: 0 }], 10);
    expect(a.ys[0]).toBe(10);
    expect(b.ys[0]).toBe(-10);
  });

  it("joins neighbour paths at their shared junction", () => {
    const j0 = { x: 200, y: 0 };
    const j1 = { x: 400, y: 0 };
    const hub = { x: 0, y: 0 };
    const a = [{ x: 400, y: -100 }, j1, j0, hub];
    const b = [{ x: 400, y: 100 }, j1, j0, hub];
    expect(joinPaths(a, b)).toEqual([{ x: 400, y: -100 }, j1, { x: 400, y: 100 }]);
    expect(joinPaths(a, [hub])).toEqual(a);
  });
});

describe("route pool lifecycle", () => {
  const route = buildRoute([{ x: 0, y: 0 }, { x: 100, y: 0 }], 0);
  const spec = (speed = 50, laneKey = 1) => ({ route, laneKey, length: 20, speed, event: ev() });

  it("spawns, travels, arrives, fades and frees", () => {
    const pool = new RoutePool(4);
    const i = pool.spawn(spec());
    expect(pool.state[i]).toBe(TRAVELING);
    pool.update(1);
    expect(pool.gx[i]).toBeCloseTo(50);
    expect(pool.alpha[i]).toBe(1);
    pool.update(1.01);
    expect(pool.state[i]).toBe(ARRIVING);
    pool.update(1);
    expect(pool.state[i]).toBe(FREE);
    expect(pool.active).toBe(0);
  });

  it("reuses slots and counts overflow instead of growing", () => {
    const pool = new RoutePool(2);
    pool.spawn(spec());
    pool.spawn(spec());
    expect(pool.spawn(spec())).toBe(-1);
    expect(pool.overflow).toBe(1);
    pool.clear();
    expect(pool.spawn(spec())).toBeGreaterThanOrEqual(0);
  });

  it("gates each lane's on-ramp independently", () => {
    const pool = new RoutePool(4);
    pool.spawn(spec(10, 1));
    expect(pool.entranceClear(1, 20, 10)).toBe(false);
    expect(pool.entranceClear(2, 20, 10)).toBe(true);
    pool.update(3.1);
    expect(pool.entranceClear(1, 20, 10)).toBe(true);
  });

  it("a fast vehicle follows a slow one in its lane instead of overlapping", () => {
    const long = buildRoute([{ x: 0, y: 0 }, { x: 1000, y: 0 }], 0);
    const pool = new RoutePool(4);
    const slow = pool.spawn({ route: long, laneKey: 1, length: 20, speed: 20, event: ev() });
    pool.update(2);
    const fast = pool.spawn({ route: long, laneKey: 1, length: 20, speed: 200, event: ev() });
    const other = pool.spawn({ route: long, laneKey: 2, length: 20, speed: 200, event: ev() });
    for (let t = 0; t < 40; t++) {
      pool.update(0.1);
      expect(pool.dist[slow]! - pool.dist[fast]!).toBeGreaterThanOrEqual(20 + FOLLOW_GAP - 1e-3);
    }
    expect(pool.dist[other]).toBeCloseTo(800, 0);
    pool.release(slow);
    const before = pool.dist[fast]!;
    pool.update(0.1);
    expect(pool.dist[fast]! - before).toBeCloseTo(20, 3);
  });

  it("accelerates away from the origin and brakes into the destination", () => {
    const long = buildRoute([{ x: 0, y: 0 }, { x: 1000, y: 0 }], 0);
    const pool = new RoutePool(2, { accelDistance: 100, brakeDistance: 100, minFactor: 0.4 });
    const i = pool.spawn({ route: long, laneKey: 1, length: 20, speed: 100, event: ev() });
    pool.update(0.1);
    const start = pool.dist[i]!;
    expect(start).toBeCloseTo(4, 3);
    for (let t = 0; t < 30; t++) pool.update(0.1);
    const before = pool.dist[i]!;
    pool.update(0.1);
    expect(pool.dist[i]! - before).toBeCloseTo(10, 3);
    while (pool.state[i] === TRAVELING && 1000 - pool.dist[i]! > 50) pool.update(0.1);
    const slow = pool.dist[i]!;
    pool.update(0.1);
    expect(pool.dist[i]! - slow).toBeLessThan(8);
  });

  it("dismisses vehicles rejected by a new filter and hit-tests the newest", () => {
    const pool = new RoutePool(3);
    const a = pool.spawn(spec());
    const b = pool.spawn(spec(50, 2));
    const rect = { x: 0, y: 0, w: 10, h: 10 };
    expect(pool.hitTest(5, 5, () => rect)).toBe(b);
    pool.dismiss(() => false);
    expect(pool.state[a]).toBe(ARRIVING);
  });
});

describe("global scene", () => {
  const devices = [
    device("self", "thisHost"),
    device("gateway", "gateway"),
    device("dev:1", "lan"),
    device("dev:2", "lan"),
    device("dev:3", "lan"),
  ];
  const scene = buildGlobalScene(devices);

  it("has infrastructure plus one building per LAN device", () => {
    const nodes = scene.model.buildings.map((b) => b.node).filter(Boolean);
    expect(nodes).toEqual(expect.arrayContaining(["self", "internet", "gateway", "dev:1", "dev:2", "dev:3"]));
  });

  it("routes internet traffic through the router interchange", () => {
    const r = scene.route(ev())!;
    expect(r.points[0]!.x).toBeLessThan(0);
    expect(r.points.some((p) => p.x === 0 && p.y === 0)).toBe(true);
    expect(r.points[r.points.length - 1]!.y).toBeLessThan(-500);
  });

  it("routes between neighbouring devices without visiting the hub", () => {
    const r = scene.route(ev({ srcNode: "dev:1", dstNode: "dev:2" }))!;
    expect(r.points.some((p) => p.x === 0 && p.y === 0)).toBe(false);
  });

  it("gives unlisted devices a path and skips loopback", () => {
    expect(scene.route(ev({ srcNode: "dev:99", dstNode: "broadcast" }))).not.toBeNull();
    expect(scene.route(ev({ srcNode: "self", dstNode: "self" }))).toBeNull();
  });

  it("caps device buildings and adds an overflow block", () => {
    const many = [
      device("self", "thisHost"),
      ...Array.from({ length: MAX_DEVICE_BUILDINGS + 5 }, (_, i) => device(`dev:${i}`, "lan", i)),
    ];
    const s = buildGlobalScene(many);
    expect(s.model.buildings.filter((b) => b.kind === "device")).toHaveLength(MAX_DEVICE_BUILDINGS);
    expect(s.model.signs.find((x) => x.id === "overflow")?.text).toBe("+5 MORE");
  });
});

describe("personal scene", () => {
  const scene = buildPersonalScene("10.0.0.5");

  it("drives incoming toward the device and outgoing away, on opposite sides", () => {
    const inc = scene.route(ev({ direction: "incoming" }))!;
    const out = scene.route(ev({ direction: "outgoing" }))!;
    expect(inc.points[0]!.y).toBeLessThan(inc.points[1]!.y);
    expect(out.points[0]!.y).toBeGreaterThan(out.points[1]!.y);
    const ri = buildRoute(inc.points, inc.offset);
    const ro = buildRoute(out.points, out.offset);
    expect(Math.sign(ri.xs[0]!)).toBe(-1);
    expect(Math.sign(ro.xs[0]!)).toBe(1);
  });

  it("leaves transit traffic off the personal highway", () => {
    expect(scene.route(ev({ direction: "transit" }))).toBeNull();
  });

  it("puts destination markers beside the road, replacing decor there", () => {
    const s = buildPersonalScene("10.0.0.5", [{ name: "github.com", bytes: 50_000 }]);
    const marker = s.model.buildings.find((b) => b.kind === "destination")!;
    expect(marker.gx).toBeLessThan(0);
    expect(s.model.signs.some((x) => x.id === "dest:github.com")).toBe(true);
    const overlaps = s.model.buildings.filter(
      (b) => b.kind === "decor" && Math.abs(b.gx - marker.gx) < (b.w + marker.w) / 2 && Math.abs(b.gy - marker.gy) < (b.d + marker.d) / 2,
    );
    expect(overlaps).toHaveLength(0);
  });
});

describe("destination towers", () => {
  const d = (name: string, bytes: number): Destination => ({ name, bytes });

  it("route matching traffic to the tower's exit, the rest to the gate", () => {
    const scene = buildGlobalScene([device("self", "thisHost")], [d("github.com", 90_000)]);
    const tower = scene.route(ev({ host: "github.com" }))!;
    const last = tower.points[tower.points.length - 1]!;
    expect(Math.abs(last.x)).toBeGreaterThan(0);
    expect(last.y).toBeGreaterThan(-500);
    const gate = scene.route(ev({ host: "other.example" }))!;
    expect(gate.points[gate.points.length - 1]!.y).toBeLessThan(-500);
    expect(tower.key).not.toBe(gate.key);
  });

  it("keeps shown towers while they stay near the top, and sorts by name", () => {
    const ranked = [d("a", 900), d("b", 800), d("c", 700), d("d", 600), d("e", 500)];
    expect(stickyDestinations([], ranked, 2).map((x) => x.name)).toEqual(["a", "b"]);
    // "d" was shown and is still within the top 2n, so it stays instead of "b".
    expect(stickyDestinations(["d", "a"], ranked, 2).map((x) => x.name)).toEqual(["a", "d"]);
    expect(stickyDestinations(["e"], ranked, 2).map((x) => x.name)).toEqual(["a", "b"]);
  });
});

describe("threat severity", () => {
  it("paints definite attacks red and look-alike signals orange", () => {
    expect(threatColor("scanner")).toBe(THREAT_COLOR);
    expect(threatColor("bruteForce")).toBe(THREAT_COLOR);
    expect(threatColor("dnsTunnel")).toBe(THREAT_MEDIUM_COLOR);
    expect(threatColor("arpSpoof")).toBe(THREAT_MEDIUM_COLOR);
  });
});

describe("elevated roads", () => {
  const e = { height: 20, rampIn: 100, rampOut: 50 };

  it("ramps smoothly up, holds, and ramps down", () => {
    expect(profileHeight(e, 0, 400)).toBe(0);
    expect(profileHeight(e, 50, 400)).toBeCloseTo(10);
    expect(profileHeight(e, 200, 400)).toBe(20);
    expect(profileHeight(e, 400, 400)).toBe(0);
    expect(profileHeight({ height: 20, rampIn: 0, rampOut: 0 }, 0, 30)).toBe(20);
  });

  it("raises only points on an elevated deck", () => {
    const ground = groundHeightFn([
      { from: { x: 0, y: 0 }, to: { x: 0, y: -400 }, width: 40, style: "highway", tint: 0, lanesPerDirection: 2, elevation: e },
      { from: { x: -100, y: -200 }, to: { x: 100, y: -200 }, width: 30, style: "street", tint: 0, lanesPerDirection: 1 },
    ]);
    expect(ground(10, -200)).toBe(20);
    expect(ground(60, -200)).toBe(0);
    expect(ground(0, 50)).toBe(0);
    expect(groundHeightFn([])(0, 0)).toBe(0);
  });

  it("puts the global internet highway on a flyover that starts at ground level", () => {
    const scene = buildGlobalScene([device("self", "thisHost")], [{ name: "a.example", bytes: 1 }]);
    const ground = groundHeightFn(scene.model.roads);
    expect(ground(0, -100)).toBeLessThan(1);
    expect(ground(0, -600)).toBeGreaterThan(15);
    const points = scene.route(ev({ host: "a.example" }))!.points;
    const door = points[points.length - 1]!;
    expect(ground(door.x, door.y)).toBeGreaterThan(15);
  });
});
