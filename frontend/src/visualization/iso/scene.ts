import type { TrafficEvent } from "../../types";
import type { Pt } from "./projection";

export type RoadStyle = "highway" | "street" | "drive";

export interface RoadSpec {
  from: Pt;
  to: Pt;
  width: number;
  style: RoadStyle;
  /** Neon edge colour. */
  tint: number;
  /** Lanes per direction (for lane markings). */
  lanesPerDirection: number;
  /** Width of the central median, if any. */
  median?: number;
  /** Directional arrows + lane lighting: [colour of traffic along from→to, colour of traffic against]. */
  flowTints?: [number, number];
}

export type BuildingKind = "self" | "router" | "internet" | "device" | "overflow" | "destination" | "decor";

export interface BuildingSpec {
  /** Map node for interactive buildings ("self", "gateway", "dev:3", "internet", "lan"). */
  node: string | null;
  kind: BuildingKind;
  /** Footprint centre and size in ground units. */
  gx: number;
  gy: number;
  w: number;
  d: number;
  h: number;
  tint: number;
}

export interface PlazaSpec {
  gx: number;
  gy: number;
  w: number;
  d: number;
  tint: number;
  ring?: boolean;
}

export type SignTone = "cyan" | "magenta" | "violet" | "amber" | "mint";

export interface SignSpec {
  /** Stable id; the overlay may fill dynamic text for known ids. */
  id: string;
  text: string;
  sub?: string;
  gx: number;
  gy: number;
  z: number;
  /** Ground axis the sign runs along (skewed like the road), or flat for labels. */
  axis: "x" | "y" | "flat";
  tone: SignTone;
  size: "lg" | "md" | "sm";
  node?: string;
}

export interface SceneModel {
  roads: RoadSpec[];
  plazas: PlazaSpec[];
  buildings: BuildingSpec[];
  signs: SignSpec[];
}

export interface RouteRequest {
  /** Vehicles with the same key share a lane and queue at its on-ramp. */
  key: string;
  points: Pt[];
  offset: number;
}

export interface Scene {
  kind: "global" | "personal";
  model: SceneModel;
  /** Returns null when the event has no place in this scene (counted as "not on map"). */
  route(ev: TrafficEvent): RouteRequest | null;
}

export const LANE_WIDTH = 15;

export const TINT = {
  cyan: 0x00e5ff,
  blue: 0x3d7bff,
  magenta: 0xff2ea6,
  violet: 0x9b5cff,
  amber: 0xffb020,
  mint: 0x4dffc3,
} as const;

/** Deterministic 0..1 hash so decorative layout is stable between rebuilds. */
export function hash01(a: number, b: number): number {
  const h = Math.imul(a * 374761393 + b * 668265263, 1274126177) >>> 0;
  return ((h ^ (h >>> 13)) >>> 0) / 0xffffffff;
}

/** Keeps a flow in one lane so a conversation reads as a stream. */
export function laneFor(flowId: number | null, packetId: number, lanes: number): number {
  const key = flowId ?? packetId;
  return (Math.imul(key >>> 0, 2654435761) >>> 0) % lanes;
}

/** Height of a destination tower: grows with the log of traffic to it. */
export function destinationHeight(bytes: number): number {
  return Math.min(200, 60 + 20 * Math.log10(1 + bytes / 1000));
}
