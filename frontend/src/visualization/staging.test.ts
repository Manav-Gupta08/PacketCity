import { describe, expect, it } from "vitest";

import type { TrafficEvent } from "../types";
import { ConvoyStaging } from "./staging";

const ev = (packetId: number, flowId: number | null, bytes = 100): TrafficEvent => ({
  packetId,
  flowId,
  timestampUs: packetId,
  direction: "incoming",
  cast: "unicast",
  class: "tcp",
  transport: "tcp",
  srcNode: "self",
  dstNode: "internet",
  src: "a",
  dst: "b",
  srcPort: 1,
  dstPort: 2,
  host: null,
  length: bytes,
  packets: 1,
  bytes,
  threat: null,
});

describe("ConvoyStaging threat", () => {
  it("keeps a convoy hostile once any merged packet was", () => {
    const s = new ConvoyStaging(10);
    s.add(ev(1, 5), 0);
    s.add({ ...ev(2, 5), threat: "scanner" }, 0);
    s.add(ev(3, 5), 0);
    const out: TrafficEvent[] = [];
    s.drain((e) => (out.push(e), true), 10);
    expect(out).toHaveLength(1);
    expect(out[0]!.threat).toBe("scanner");
  });
});

describe("ConvoyStaging", () => {
  it("merges waiting events per flow and carriageway, preserving counts", () => {
    const s = new ConvoyStaging(10);
    s.add(ev(1, 5), 0);
    s.add(ev(2, 5), 0);
    s.add(ev(3, 5), 1);
    s.add(ev(4, 6), 0);
    expect(s.size).toBe(3);
    const out: TrafficEvent[] = [];
    s.drain((e) => (out.push(e), true), 10);
    expect(out.map((e) => e.packets)).toEqual([2, 1, 1]);
    expect(out[0]!.packetId).toBe(2);
    expect(out[0]!.bytes).toBe(200);
    expect(s.merged).toBe(1);
    expect(s.size).toBe(0);
  });

  it("keeps blocked entries and respects the budget", () => {
    const s = new ConvoyStaging(10);
    for (let i = 0; i < 5; i++) s.add(ev(i, i), i % 2);
    const spawned = s.drain((_, lane) => lane === 1, 1);
    expect(spawned).toBe(1);
    expect(s.size).toBe(4);
  });

  it("bounds the number of distinct keys", () => {
    const s = new ConvoyStaging(2);
    for (let i = 0; i < 50; i++) s.add(ev(i, i), 0);
    expect(s.size).toBe(3);
    let packets = 0;
    s.drain((e) => ((packets += e.packets), true), 10);
    expect(packets).toBe(50);
  });
});
