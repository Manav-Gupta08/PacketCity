import type { Direction } from "../types";

/** Personal-mode carriageways. Transit traffic is not on this machine's highway. */
export type Carriageway = "incoming" | "outgoing";

export const SUB_LANES = 3;

/** Local (loopback) traffic is produced by this machine, so it drives on the outgoing side. */
export function carriagewayFor(direction: Direction): Carriageway | null {
  switch (direction) {
    case "incoming":
      return "incoming";
    case "outgoing":
    case "local":
      return "outgoing";
    case "transit":
      return null;
  }
}
