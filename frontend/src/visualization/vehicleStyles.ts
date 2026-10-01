import type { ThreatKind, TrafficClass } from "../types";

/**
 * Visual metaphor for each traffic class. Documented in docs/VISUAL_MAPPING.md.
 * Shape carries meaning independently of colour so classes stay distinguishable for
 * colour-blind users.
 */
export type VehicleShape = "sedan" | "compact" | "dart" | "diamond" | "hex" | "van";

/** 3D silhouette. Protocol picks the model; large merged convoys become haulers. */
export type CarModel = "coupe" | "sedan" | "compact" | "bike" | "interceptor" | "van" | "hauler";

export interface VehicleStyle {
  label: string;
  shape: VehicleShape;
  model: CarModel;
  color: number;
  glow: boolean;
  /** Relative travel speed; 1 = baseline trip time. */
  speed: number;
}

export const VEHICLE_STYLES: Record<TrafficClass, VehicleStyle> = {
  https: { label: "HTTPS / TLS", shape: "sedan", model: "coupe", color: 0x00d9ff, glow: true, speed: 1 },
  http: { label: "HTTP", shape: "sedan", model: "sedan", color: 0x3d7bff, glow: false, speed: 1 },
  tcp: { label: "TCP", shape: "sedan", model: "sedan", color: 0x9466ff, glow: false, speed: 1 },
  udp: { label: "UDP", shape: "compact", model: "compact", color: 0xff8a1f, glow: false, speed: 1.1 },
  dns: { label: "DNS", shape: "dart", model: "bike", color: 0x3dff8a, glow: false, speed: 1.45 },
  icmp: { label: "ICMP", shape: "diamond", model: "interceptor", color: 0xff3d7a, glow: false, speed: 1.2 },
  arp: { label: "ARP", shape: "hex", model: "van", color: 0xffd23f, glow: false, speed: 0.9 },
  dhcp: { label: "DHCP", shape: "van", model: "van", color: 0xd8e1ff, glow: false, speed: 0.85 },
  other: { label: "Other", shape: "compact", model: "compact", color: 0x7d8aa8, glow: false, speed: 1 },
};

/** Hostile traffic overrides the protocol colour; the model still shows the protocol. */
export const THREAT_COLOR = 0xff1a2e;

export const THREAT_LABELS: Record<ThreatKind, { title: string; detail: string }> = {
  scanner: { title: "Scanner", detail: "The sender was caught port-scanning or sweeping hosts within the last 5 minutes." },
  stealthScan: { title: "Stealth scan probe", detail: "Illegal TCP flag combination (NULL, FIN, XMAS, SYN+FIN or SYN+RST) used by stealth port scanners." },
  land: { title: "LAND packet", detail: "Source and destination address and port are identical, a classic denial-of-service trick." },
  backdoorPort: { title: "Backdoor port", detail: "Uses a port associated with well-known backdoors, RATs or botnet C2 (e.g. 4444, 31337, 6667)." },
  arpSpoof: { title: "Possible ARP spoofing", detail: "ARP from an address that two different MACs claim." },
};

/** Convoys at least this long (ground units) and carrying several packets drive as haulers. */
const HAULER_MIN_LENGTH = 30;
const HAULER_MIN_PACKETS = 4;

export function carModelFor(cls: TrafficClass, packets: number, length: number): CarModel {
  return packets >= HAULER_MIN_PACKETS && length >= HAULER_MIN_LENGTH ? "hauler" : VEHICLE_STYLES[cls].model;
}

export const cssColor = (c: number): string => `#${c.toString(16).padStart(6, "0")}`;

const MIN_BYTES = 60;
/** Upper bound for scaling; aggregated convoys can exceed one MTU. */
const MAX_BYTES = 64 * 1024;
/** Vehicle length in ground units. */
export const MIN_VEHICLE_LENGTH = 14;
export const MAX_VEHICLE_LENGTH = 44;
/** Baseline cruising speed, ground units per second. */
export const BASE_GROUND_SPEED = 190;
/** Heavier vehicles are slower by up to this fraction. */
const HEAVY_SLOWDOWN = 0.3;
/** Busier roads flow faster by up to this fraction. */
const RATE_SPEEDUP = 0.6;

/** Log-scaled so a 1500-byte segment is clearly bigger than a 60-byte ACK without dwarfing it. */
export function sizeFactor(bytes: number): number {
  const clamped = Math.min(MAX_BYTES, Math.max(MIN_BYTES, bytes));
  return Math.log(clamped / MIN_BYTES) / Math.log(MAX_BYTES / MIN_BYTES);
}

export function vehicleLength(bytes: number): number {
  return MIN_VEHICLE_LENGTH + (MAX_VEHICLE_LENGTH - MIN_VEHICLE_LENGTH) * Math.sqrt(sizeFactor(bytes));
}

/** Ground units per second. */
export function vehicleSpeed(cls: TrafficClass, bytes: number, packetsPerSec: number): number {
  const heavy = 1 - HEAVY_SLOWDOWN * sizeFactor(bytes);
  const busy = 1 + RATE_SPEEDUP * Math.min(1, Math.log10(1 + packetsPerSec) / 4);
  return BASE_GROUND_SPEED * VEHICLE_STYLES[cls].speed * heavy * busy;
}
