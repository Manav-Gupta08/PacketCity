import type { DeviceSnapshot, TrafficEvent } from "../../types";
import type { Destination } from "../destinations";
import type { Pt } from "../iso/projection";
import { joinPaths } from "../iso/routes";
import {
  destinationHeight,
  hash01,
  LANE_WIDTH,
  laneFor,
  TINT,
  type BuildingSpec,
  type PlazaSpec,
  type RoadSpec,
  type Scene,
  type SceneModel,
  type SignSpec,
} from "../iso/scene";

/**
 * Global network city. The router is a central interchange with four arms:
 *   -gy (up-right)   elevated INTERNET highway
 *   -gx (up-left)    road to YOUR DEVICE
 *   +gx (down-right) LOCAL DEVICES avenue, one building per LAN device on side streets
 *   +gy (down-left)  BROADCAST plaza (broadcast / multicast destinations)
 */

const LANES_PER_DIRECTION = 2;
const ROAD_WIDTH = 2 * LANES_PER_DIRECTION * LANE_WIDTH;
const HUB = 95;
const INTERNET_ROAD_END = 760;
const SELF_ROAD_END = 430;
const BROADCAST_ROAD_END = 380;
const AVENUE_FIRST = HUB + 110;
const AVENUE_SPACING = 138;
const DRIVE_LENGTH = 92;
const DEVICE_SIZE = 84;
/** LAN devices shown as buildings; the rest share the "+N more" block. */
export const MAX_DEVICE_BUILDINGS = 14;
const BYTES_PER_HEIGHT_DECADE = 22;
/** Destination towers line the internet highway in pairs, past the flyover's cross street. */
const DEST_FIRST_Y = -HUB - 300;
const DEST_SPACING = 140;
const DEST_SIZE = 70;
const DEST_DRIVE = 34;
const HIGHWAY_HALF_WIDTH = (ROAD_WIDTH + 24) / 2;
/** The internet highway climbs out of the interchange onto a flyover and stays elevated. */
const FLYOVER_HEIGHT = 22;
const FLYOVER_RAMP = 160;
/** Ground-level street passing under the flyover (scenery; no traffic is routed on it). */
const UNDERPASS_Y = -HUB - 215;
const UNDERPASS_HALF_LENGTH = 230;
/** Skybridges run past the door into the tower facade. */
const SKYBRIDGE_REACH = 10;

const HUB_POINT: Pt = { x: 0, y: 0 };

function deviceHeight(d: DeviceSnapshot): number {
  const bytes = d.bytesSent + d.bytesReceived;
  return Math.min(230, 55 + BYTES_PER_HEIGHT_DECADE * Math.log10(1 + bytes / 100));
}

function pickDevices(devices: DeviceSnapshot[]): { shown: DeviceSnapshot[]; hidden: number } {
  const lan = devices.filter((d) => d.role === "lan");
  if (lan.length <= MAX_DEVICE_BUILDINGS) return { shown: lan, hidden: 0 };
  const busiest = new Set(
    [...lan]
      .sort((a, b) => b.bytesSent + b.bytesReceived - (a.bytesSent + a.bytesReceived))
      .slice(0, MAX_DEVICE_BUILDINGS)
      .map((d) => d.node),
  );
  // Keep discovery order among the chosen so buildings don't reshuffle on every update.
  return { shown: lan.filter((d) => busiest.has(d.node)), hidden: lan.length - MAX_DEVICE_BUILDINGS };
}

/** A decor block of height h standing D ground units in front of content hides it when h > D·ISO_S. */
const FRONT_HEIGHT_PER_DISTANCE = 0.4;

function decor(model: SceneModel, avenueEnd: number): void {
  const southRow = DRIVE_LENGTH + DEVICE_SIZE + 12;
  // Quadrants between the arms, kept clear of roads and device rows. The last value is the
  // depth (gx + gy) of the content each zone sits in front of, or null for zones behind it.
  const zones: [number, number, number, number, number | null][] = [
    [-SELF_ROAD_END - 180, -INTERNET_ROAD_END + 40, -260, -260, null],
    [260, -INTERNET_ROAD_END + 40, avenueEnd + 120, -DRIVE_LENGTH - DEVICE_SIZE - 90, null],
    [-SELF_ROAD_END - 180, 180, -150, BROADCAST_ROAD_END + 260, 0],
    [180, southRow + 90, avenueEnd + 120, BROADCAST_ROAD_END + 260, southRow],
  ];
  const cell = 120;
  zones.forEach(([x0, y0, x1, y1, frontOf], z) => {
    for (let x = x0; x < x1 - cell / 2; x += cell) {
      for (let y = y0; y < y1 - cell / 2; y += cell) {
        const r = hash01(Math.round(x), Math.round(y) + z * 7919);
        if (r < 0.35) continue;
        const size = 50 + r * 40;
        const gy = y + cell / 2;
        const tall = 60 + r * r * 260;
        const h = frontOf === null ? tall : Math.min(tall, Math.max(18, (gy - size / 2 - frontOf) * FRONT_HEIGHT_PER_DISTANCE));
        model.buildings.push({
          node: null,
          kind: "decor",
          gx: x + cell / 2,
          gy,
          w: size,
          d: size * (0.8 + hash01(z, Math.round(x)) * 0.4),
          h,
          tint: r > 0.8 ? TINT.magenta : r > 0.6 ? TINT.violet : TINT.blue,
        });
      }
    }
  });
}

export function buildGlobalScene(devices: DeviceSnapshot[], destinations: readonly Destination[] = []): Scene {
  const { shown, hidden } = pickDevices(devices);
  const self = devices.find((d) => d.role === "thisHost");
  const gateway = devices.find((d) => d.role === "gateway");
  const columns = Math.max(1, Math.ceil(shown.length / 2));
  const junction = (c: number): Pt => ({ x: AVENUE_FIRST + c * AVENUE_SPACING, y: 0 });
  const overflowColumn = hidden > 0 ? columns : -1;
  const avenueEnd = junction(Math.max(columns, overflowColumn + 1) - 1).x + 110;

  const roads: RoadSpec[] = [
    { from: { x: 0, y: -HUB }, to: { x: 0, y: -INTERNET_ROAD_END }, width: ROAD_WIDTH + 24, style: "highway", tint: TINT.cyan, lanesPerDirection: 2, median: 10, flowTints: [TINT.cyan, TINT.magenta], elevation: { height: FLYOVER_HEIGHT, rampIn: FLYOVER_RAMP, rampOut: 0 } },
    { from: { x: -UNDERPASS_HALF_LENGTH, y: UNDERPASS_Y }, to: { x: UNDERPASS_HALF_LENGTH, y: UNDERPASS_Y }, width: 2 * LANE_WIDTH, style: "street", tint: TINT.violet, lanesPerDirection: 1 },
    { from: { x: -HUB, y: 0 }, to: { x: -SELF_ROAD_END, y: 0 }, width: ROAD_WIDTH, style: "street", tint: TINT.cyan, lanesPerDirection: 2 },
    { from: { x: HUB, y: 0 }, to: { x: avenueEnd, y: 0 }, width: ROAD_WIDTH, style: "street", tint: TINT.magenta, lanesPerDirection: 2 },
    { from: { x: 0, y: HUB }, to: { x: 0, y: BROADCAST_ROAD_END }, width: ROAD_WIDTH, style: "street", tint: TINT.violet, lanesPerDirection: 2 },
  ];
  const plazas: PlazaSpec[] = [
    { gx: 0, gy: 0, w: HUB * 2, d: HUB * 2, tint: TINT.cyan, ring: true },
    { gx: 0, gy: BROADCAST_ROAD_END + 70, w: 220, d: 140, tint: TINT.violet },
  ];
  const buildings: BuildingSpec[] = [
    { node: "self", kind: "self", gx: -SELF_ROAD_END - 90, gy: 0, w: 150, d: 150, h: 250, tint: TINT.cyan },
    { node: "internet", kind: "internet", gx: 0, gy: -INTERNET_ROAD_END - 70, w: 260, d: 110, h: 170, tint: TINT.cyan },
    { node: "gateway", kind: "router", gx: -HUB - 95, gy: -HUB - 95, w: 110, d: 110, h: 120, tint: TINT.magenta },
  ];
  const signs: SignSpec[] = [
    { id: "internet", text: "INTERNET", gx: 40, gy: -INTERNET_ROAD_END + 60, z: 150, axis: "y", tone: "cyan", size: "lg", node: "internet" },
    { id: "router", text: "ROUTER", sub: gateway?.label ?? "gateway", gx: -HUB - 95, gy: -HUB - 95, z: 150, axis: "x", tone: "magenta", size: "lg", node: "gateway" },
    { id: "self", text: "YOUR DEVICE", sub: self?.label ?? "", gx: -SELF_ROAD_END - 90, gy: 0, z: 285, axis: "flat", tone: "cyan", size: "lg", node: "self" },
    { id: "lan", text: "LOCAL DEVICES", gx: AVENUE_FIRST + 40, gy: 70, z: 70, axis: "x", tone: "magenta", size: "md" },
    { id: "broadcast", text: "LAN BROADCAST", sub: "broadcast · multicast", gx: 0, gy: BROADCAST_ROAD_END + 70, z: 40, axis: "flat", tone: "violet", size: "md", node: "broadcast" },
  ];

  const paths = new Map<string, Pt[]>();
  paths.set("self", [{ x: -SELF_ROAD_END + 5, y: 0 }, HUB_POINT]);
  paths.set("internet", [{ x: 0, y: -INTERNET_ROAD_END + 10 }, HUB_POINT]);
  paths.set("gateway", [HUB_POINT]);
  paths.set("broadcast", [{ x: 0, y: BROADCAST_ROAD_END + 20 }, HUB_POINT]);
  const avenueBack = (c: number): Pt[] => [...Array.from({ length: c + 1 }, (_, k) => junction(c - k)), HUB_POINT];

  shown.forEach((d, k) => {
    const c = Math.floor(k / 2);
    const side = k % 2 === 0 ? -1 : 1;
    const j = junction(c);
    const door: Pt = { x: j.x, y: side * DRIVE_LENGTH };
    roads.push({ from: j, to: door, width: ROAD_WIDTH - 8, style: "drive", tint: TINT.violet, lanesPerDirection: 1 });
    buildings.push({
      node: d.node,
      kind: "device",
      gx: j.x,
      gy: side * (DRIVE_LENGTH + DEVICE_SIZE / 2 + 12),
      w: DEVICE_SIZE,
      d: DEVICE_SIZE,
      h: deviceHeight(d),
      tint: side < 0 ? TINT.violet : TINT.magenta,
    });
    signs.push({
      id: `dev:${d.node}`,
      text: d.label,
      gx: j.x,
      gy: side * (DRIVE_LENGTH + DEVICE_SIZE / 2 + 12),
      z: deviceHeight(d) + 26,
      axis: "flat",
      tone: side < 0 ? "violet" : "magenta",
      size: "sm",
      node: d.node,
    });
    paths.set(d.node, [door, ...avenueBack(c)]);
  });

  if (hidden > 0) {
    const j = junction(overflowColumn);
    const end: Pt = { x: j.x + 60, y: 0 };
    buildings.push({ node: "lan", kind: "overflow", gx: j.x + 130, gy: 0, w: 80, d: 120, h: 70, tint: TINT.magenta });
    signs.push({ id: "overflow", text: `+${hidden} MORE`, gx: j.x + 130, gy: 0, z: 100, axis: "flat", tone: "magenta", size: "sm", node: "lan" });
    paths.set("lan", [end, ...avenueBack(overflowColumn)]);
  }

  // Traffic to a destination with a tower takes its exit instead of driving to the INTERNET gate.
  destinations.forEach((dst, k) => {
    const side = k % 2 === 0 ? 1 : -1;
    const y = DEST_FIRST_Y - Math.floor(k / 2) * DEST_SPACING;
    const door: Pt = { x: side * (HIGHWAY_HALF_WIDTH + DEST_DRIVE), y };
    const gx = side * (HIGHWAY_HALF_WIDTH + DEST_DRIVE + DEST_SIZE / 2 + 8);
    const h = destinationHeight(dst.bytes);
    roads.push({ from: { x: side * HIGHWAY_HALF_WIDTH, y }, to: { x: side * (HIGHWAY_HALF_WIDTH + DEST_DRIVE + SKYBRIDGE_REACH), y }, width: 34, style: "drive", tint: TINT.amber, lanesPerDirection: 1, elevation: { height: FLYOVER_HEIGHT, rampIn: 0, rampOut: 0 } });
    buildings.push({ node: "internet", kind: "destination", gx, gy: y, w: DEST_SIZE, d: DEST_SIZE, h, tint: TINT.amber });
    signs.push({ id: `dest:${dst.name}`, text: dst.name, gx, gy: y, z: h + 24, axis: "flat", tone: "amber", size: "sm", node: "internet" });
    paths.set(`dest:${dst.name}`, [door, { x: 0, y }, HUB_POINT]);
  });

  const model: SceneModel = { roads, plazas, buildings, signs };
  decor(model, avenueEnd);

  // Devices seen in traffic before the next device-list update (or beyond the cap) use the avenue.
  const unlisted = paths.get("lan") ?? [{ x: AVENUE_FIRST - 50, y: 0 }, HUB_POINT];
  const pathFor = (node: string): Pt[] | undefined =>
    paths.get(node) ?? (node.startsWith("dev:") || node === "lan" ? unlisted : undefined);

  return {
    kind: "global",
    model,
    route(ev: TrafficEvent) {
      if (ev.srcNode === ev.dstNode) return null;
      const toTower = (node: string) => (node === "internet" && ev.host && paths.has(`dest:${ev.host}`) ? `dest:${ev.host}` : node);
      const srcNode = toTower(ev.srcNode);
      const dstNode = toTower(ev.dstNode);
      const src = pathFor(srcNode);
      const dst = pathFor(dstNode);
      if (!src || !dst) return null;
      const lane = laneFor(ev.flowId, ev.packetId, LANES_PER_DIRECTION);
      return {
        key: `${srcNode}>${dstNode}:${lane}`,
        points: joinPaths(src, dst),
        offset: LANE_WIDTH * (0.5 + lane),
      };
    },
  };
}
