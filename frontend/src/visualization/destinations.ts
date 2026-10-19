import type { FlowSnapshot } from "../types";

export interface Destination {
  name: string;
  bytes: number;
}

/** Destination towers shown along the internet road. */
export const MAX_DESTINATIONS = 6;

/** Flows whose hostname names an internet destination (not DNS questions, mDNS or reverse lookups). */
export function internetHostnames(flows: FlowSnapshot[]): FlowSnapshot[] {
  return flows.filter((f) => f.hostname && f.class !== "dns" && !/\.(local|arpa)$/i.test(f.hostname));
}

export function rankDestinations(flows: FlowSnapshot[]): Destination[] {
  const bytes = new Map<string, number>();
  for (const f of internetHostnames(flows)) bytes.set(f.hostname!, (bytes.get(f.hostname!) ?? 0) + f.bytes);
  return [...bytes].map(([name, b]) => ({ name, bytes: b })).sort((a, b) => b.bytes - a.bytes || (a.name < b.name ? -1 : 1));
}

/**
 * Top `n` destinations with hysteresis: a tower already shown stays while it ranks within the
 * top 2n, so towers don't swap places every time two hosts trade ranks. Result is name-sorted so
 * a given set always gets the same positions.
 */
export function stickyDestinations(previous: readonly string[], ranked: Destination[], n = MAX_DESTINATIONS): Destination[] {
  const keepWindow = new Map(ranked.slice(0, 2 * n).map((d) => [d.name, d]));
  const kept = previous.map((name) => keepWindow.get(name)).filter((d): d is Destination => !!d).slice(0, n);
  const names = new Set(kept.map((d) => d.name));
  for (const d of ranked) {
    if (kept.length >= n) break;
    if (!names.has(d.name)) {
      kept.push(d);
      names.add(d.name);
    }
  }
  return kept.sort((a, b) => (a.name < b.name ? -1 : 1));
}
