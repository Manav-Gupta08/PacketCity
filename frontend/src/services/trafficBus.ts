import type { TrafficEvent } from "../types";

/**
 * Bounded FIFO between the IPC stream and the renderer. Events never pass through React state.
 * When full, the oldest events are discarded (and counted) so memory stays bounded while the
 * renderer is paused or overloaded.
 */
export class TrafficBus {
  private readonly buf: (TrafficEvent | undefined)[];
  private head = 0;
  private size = 0;
  dropped = 0;

  constructor(readonly capacity: number) {
    this.buf = new Array(capacity);
  }

  get length(): number {
    return this.size;
  }

  push(events: readonly TrafficEvent[]): void {
    for (const ev of events) {
      if (this.size === this.capacity) {
        this.head = (this.head + 1) % this.capacity;
        this.size--;
        this.dropped += ev.packets;
      }
      this.buf[(this.head + this.size) % this.capacity] = ev;
      this.size++;
    }
  }

  shift(): TrafficEvent | undefined {
    if (this.size === 0) return undefined;
    const ev = this.buf[this.head];
    this.buf[this.head] = undefined;
    this.head = (this.head + 1) % this.capacity;
    this.size--;
    return ev;
  }

  /** Puts an event back at the front (used when every lane entrance is blocked). */
  unshift(ev: TrafficEvent): void {
    if (this.size === this.capacity) {
      this.dropped += ev.packets;
      return;
    }
    this.head = (this.head - 1 + this.capacity) % this.capacity;
    this.buf[this.head] = ev;
    this.size++;
  }

  clear(): void {
    this.buf.fill(undefined);
    this.head = 0;
    this.size = 0;
  }
}

/** Queue capacity: a few seconds of rendering backlog at typical spawn rates. */
export const trafficBus = new TrafficBus(2048);
