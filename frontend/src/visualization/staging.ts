import type { TrafficEvent } from "../types";

/**
 * Holds events waiting for road space. Events for the same flow and carriageway merge into one
 * "convoy" while they wait, so when traffic exceeds what the road can show, vehicles get bigger
 * instead of the queue growing. Packet and byte counts are always preserved.
 */
export class ConvoyStaging {
  private readonly entries = new Map<string, { lane: number; event: TrafficEvent }>();
  /** Packets merged into an existing convoy rather than getting their own vehicle. */
  merged = 0;

  constructor(private readonly maxKeys: number) {}

  get size(): number {
    return this.entries.size;
  }

  /** `lane` identifies where the vehicle will drive; merging never crosses lanes. */
  add(event: TrafficEvent, lane: number): void {
    let key = `${lane}:${event.flowId ?? `c:${event.class}`}`;
    if (!this.entries.has(key) && this.entries.size >= this.maxKeys) {
      key = `${lane}:overflow:${event.class}`;
    }
    const existing = this.entries.get(key);
    if (!existing) {
      this.entries.set(key, { lane, event: { ...event } });
      return;
    }
    const e = existing.event;
    e.packets += event.packets;
    e.bytes += event.bytes;
    e.packetId = event.packetId;
    e.timestampUs = event.timestampUs;
    e.length = event.length;
    e.threat = e.threat ?? event.threat;
    this.merged += event.packets;
  }

  /** Visits waiting convoys oldest-first; returning true from `trySpawn` removes the entry. */
  drain(trySpawn: (event: TrafficEvent, lane: number) => boolean, budget: number): number {
    let spawned = 0;
    for (const [key, entry] of this.entries) {
      if (spawned >= budget) break;
      if (trySpawn(entry.event, entry.lane)) {
        this.entries.delete(key);
        spawned++;
      }
    }
    return spawned;
  }

  clear(): void {
    this.entries.clear();
  }
}
