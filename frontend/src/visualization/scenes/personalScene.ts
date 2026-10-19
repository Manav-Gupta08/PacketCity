import type { TrafficEvent } from "../../types";
import type { Destination } from "../destinations";
import type { Pt } from "../iso/projection";
import { destinationHeight, hash01, LANE_WIDTH, laneFor, TINT, type BuildingSpec, type Scene, type SceneModel, type SignSpec } from "../iso/scene";
import { carriagewayFor, SUB_LANES } from "../lanes";

/**
 * Personal highway: one two-carriageway road between YOUR DEVICE (bottom-left) and the
 * INTERNET gate (top-right), running along the ground y axis.
 * Incoming drives +gy (toward the device) on the -gx side; outgoing drives -gy on the +gx side.
 */

const HALF_LENGTH = 560;
const MEDIAN = 18;
const CARRIAGEWAY = SUB_LANES * LANE_WIDTH;
const ROAD_WIDTH = 2 * CARRIAGEWAY + MEDIAN;
const INTERNET_END: Pt = { x: 0, y: -HALF_LENGTH };
const DEVICE_END: Pt = { x: 0, y: HALF_LENGTH };

/** A front-side building of height h at ground distance D hides the road when h > D·ISO_S. */
const FRONT_HEIGHT_PER_DISTANCE = 0.4;
const DECOR_START = -HALF_LENGTH + 40;
const DECOR_STEP = 130;
const ROAD_CLEARANCE = ROAD_WIDTH / 2 + 70;
/** Destination markers take the first back-row slots nearest the INTERNET gate. */
const MAX_MARKERS = 4;
const MARKER_SIZE = 76;

function decor(reservedBackSlots: number): BuildingSpec[] {
  const out: BuildingSpec[] = [];
  for (let side = -1; side <= 1; side += 2) {
    for (let row = 0; row < 2; row++) {
      for (let y = DECOR_START, slot = 0; y < HALF_LENGTH - 80; y += DECOR_STEP, slot++) {
        if (side < 0 && row === 0 && slot < reservedBackSlots) continue;
        const r = hash01(y + row * 31, side * 17);
        if (r < 0.3) continue;
        const size = 60 + r * 36;
        const gx = side * (ROAD_CLEARANCE + size / 2 + row * 140);
        const tall = 50 + r * r * (row === 0 ? 180 : 300);
        // The +gx side is nearer the viewer, so keep it low enough to see the lanes over it.
        const h = side > 0 ? Math.min(tall, (Math.abs(gx) - size / 2) * FRONT_HEIGHT_PER_DISTANCE) : tall;
        out.push({ node: null, kind: "decor", gx, gy: y + r * 40, w: size, d: size, h, tint: side < 0 ? TINT.magenta : TINT.cyan });
      }
    }
  }
  return out;
}

export function buildPersonalScene(localLabel: string, destinations: readonly Destination[] = []): Scene {
  const markers = destinations.slice(0, MAX_MARKERS);
  const markerBuildings: BuildingSpec[] = [];
  const markerSigns: SignSpec[] = [];
  markers.forEach((dst, k) => {
    const gx = -(ROAD_CLEARANCE + MARKER_SIZE / 2);
    const gy = DECOR_START + k * DECOR_STEP + 20;
    const h = destinationHeight(dst.bytes);
    markerBuildings.push({ node: "internet", kind: "destination", gx, gy, w: MARKER_SIZE, d: MARKER_SIZE, h, tint: TINT.amber });
    markerSigns.push({ id: `dest:${dst.name}`, text: dst.name, gx, gy, z: h + 24, axis: "flat", tone: "amber", size: "sm", node: "internet" });
  });
  const model: SceneModel = {
    roads: [
      { from: INTERNET_END, to: DEVICE_END, width: ROAD_WIDTH, style: "highway", tint: TINT.cyan, lanesPerDirection: SUB_LANES, median: MEDIAN, flowTints: [TINT.magenta, TINT.cyan] },
    ],
    plazas: [],
    buildings: [
      { node: "self", kind: "self", gx: 0, gy: HALF_LENGTH + 110, w: 190, d: 170, h: 260, tint: TINT.cyan },
      { node: "internet", kind: "internet", gx: 0, gy: -HALF_LENGTH - 80, w: ROAD_WIDTH + 140, d: 110, h: 170, tint: TINT.magenta },
      ...markerBuildings,
      ...decor(markers.length),
    ],
    signs: [
      { id: "self", text: "YOUR DEVICE", sub: localLabel, gx: 0, gy: HALF_LENGTH + 110, z: 295, axis: "flat", tone: "cyan", size: "lg", node: "self" },
      { id: "internet", text: "INTERNET", gx: 0, gy: -HALF_LENGTH - 80, z: 200, axis: "flat", tone: "magenta", size: "lg", node: "internet" },
      { id: "in", text: "◀ INCOMING", gx: -ROAD_WIDTH / 2 - 26, gy: -HALF_LENGTH + 220, z: 6, axis: "y", tone: "magenta", size: "md" },
      { id: "out", text: "OUTGOING ▶", gx: ROAD_WIDTH / 2 + 26, gy: HALF_LENGTH - 260, z: 6, axis: "y", tone: "cyan", size: "md" },
      ...markerSigns,
    ],
  };

  return {
    kind: "personal",
    model,
    route(ev: TrafficEvent) {
      const cw = carriagewayFor(ev.direction);
      if (cw === null) return null;
      const sub = laneFor(ev.flowId, ev.packetId, SUB_LANES);
      const offset = MEDIAN / 2 + LANE_WIDTH * (0.5 + sub);
      return cw === "incoming"
        ? { key: `in:${sub}`, points: [INTERNET_END, DEVICE_END], offset }
        : { key: `out:${sub}`, points: [DEVICE_END, INTERNET_END], offset };
    },
  };
}
