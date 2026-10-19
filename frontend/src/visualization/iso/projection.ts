/**
 * Isometric projection. Ground plane (gx, gy) with z up. Screen y grows with gx + gy, so the
 * viewer looks from the +gx/+gy corner; faces facing +gx and +gy are the visible sides.
 *
 *   +gx → down-right   +gy → down-left   -gx → up-left   -gy → up-right
 */
export const ISO_C = Math.cos(Math.PI / 6);
export const ISO_S = 0.5;

export interface Pt {
  x: number;
  y: number;
}

export function project(gx: number, gy: number, z = 0): Pt {
  return { x: (gx - gy) * ISO_C, y: (gx + gy) * ISO_S - z };
}

/** Inverse of `project` for z = 0. */
export function unproject(sx: number, sy: number): Pt {
  const a = sx / ISO_C;
  const b = sy / ISO_S;
  return { x: (a + b) / 2, y: (b - a) / 2 };
}

/** Painter's-algorithm depth: larger is nearer the viewer. */
export const depthOf = (gx: number, gy: number): number => gx + gy;

/** Four ground headings; sprites are drawn along +gx and mirrored/rotated for the others. */
export const Heading = { PosX: 0, PosY: 1, NegX: 2, NegY: 3 } as const;
export type Heading = (typeof Heading)[keyof typeof Heading];

export function headingOf(dx: number, dy: number): Heading {
  if (Math.abs(dx) >= Math.abs(dy)) return dx >= 0 ? Heading.PosX : Heading.NegX;
  return dy >= 0 ? Heading.PosY : Heading.NegY;
}
