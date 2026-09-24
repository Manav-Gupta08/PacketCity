import { describe, expect, it } from "vitest";

import { TrafficBus } from "./trafficBus";
import type { TrafficEvent } from "../types";

const ev = (packetId: number): TrafficEvent => ({
  packetId,
  flowId: null,
  timestampUs: 0,
  direction: "incoming",
  cast: "unicast",
  class: "udp",
  transport: "udp",
  srcNode: "internet",
  dstNode: "self",
  src: "a",
  dst: "b",
  srcPort: null,
  dstPort: null,
  host: null,
  length: 60,
  packets: 1,
  bytes: 60,
});

describe("TrafficBus", () => {
  it("is FIFO and bounded, dropping the oldest", () => {
    const bus = new TrafficBus(3);
    bus.push([ev(1), ev(2), ev(3), ev(4)]);
    expect(bus.length).toBe(3);
    expect(bus.dropped).toBe(1);
    expect(bus.shift()?.packetId).toBe(2);
    bus.unshift(ev(9));
    expect(bus.shift()?.packetId).toBe(9);
    expect(bus.shift()?.packetId).toBe(3);
    expect(bus.shift()?.packetId).toBe(4);
    expect(bus.shift()).toBeUndefined();
  });
});
