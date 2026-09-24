import * as THREE from "three";

/** Deterministic PRNG so the generated city looks the same on every rebuild. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function canvas(w: number, h: number): [HTMLCanvasElement, CanvasRenderingContext2D] {
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  return [c, c.getContext("2d")!];
}

function texture(c: HTMLCanvasElement, srgb = true, repeat = false): THREE.CanvasTexture {
  const t = new THREE.CanvasTexture(c);
  if (srgb) t.colorSpace = THREE.SRGBColorSpace;
  if (repeat) t.wrapS = t.wrapT = THREE.RepeatWrapping;
  t.anisotropy = 4;
  return t;
}

/** One facade tile covers this many world units; UVs are generated in world space. */
export const FACADE_TILE_W = 160;
export const FACADE_TILE_H = 224;
const BAYS = 32;
const FLOORS = 32;

export type FacadePalette = "warm" | "cool" | "neon";

const LIT: Record<FacadePalette, string[]> = {
  warm: ["#ffd9a0", "#ffe9c4", "#ffc98a", "#fff2dc"],
  cool: ["#bfe4ff", "#dcefff", "#a6d6ff", "#eef6ff"],
  neon: ["#ffd0ee", "#c8f2ff", "#e2d6ff", "#f4f0ff", "#ff7ad9"],
};

export interface Facade {
  map: THREE.Texture;
  emissive: THREE.Texture;
}

/**
 * Curtain-wall facade: albedo has glass panes and mullions, emissive has lit windows grouped the
 * way offices light up (whole floors, clusters, the odd lone window). Texel (0,0) stays dark and
 * is used for roofs.
 */
export function facadeTextures(palette: FacadePalette, seed: number): Facade {
  const cw = 8;
  const ch = 16;
  const [a, ag] = canvas(BAYS * cw, FLOORS * ch);
  const [e, eg] = canvas(BAYS * cw, FLOORS * ch);
  const r = rng(seed);
  ag.fillStyle = "#0a1122";
  ag.fillRect(0, 0, a.width, a.height);
  eg.fillStyle = "#000";
  eg.fillRect(0, 0, e.width, e.height);
  const colors = LIT[palette];
  for (let f = 0; f < FLOORS; f++) {
    const floorLit = r();
    const density = floorLit > 0.9 ? 0.75 : floorLit > 0.55 ? 0.22 : 0.035;
    for (let b = 0; b < BAYS; b++) {
      const x = b * cw;
      const y = f * ch;
      const pane = 10 + Math.floor(r() * 14);
      ag.fillStyle = `rgb(${pane}, ${pane + 10}, ${pane + 28})`;
      ag.fillRect(x + 1, y + 2, cw - 2, ch - 4);
      if (b === 0 && f === 0) continue;
      if (r() < density) {
        const c = colors[Math.floor(r() * colors.length)]!;
        eg.globalAlpha = 0.35 + r() * 0.45;
        eg.fillStyle = c;
        // Window band sits in the upper part of the storey; spandrels stay dark.
        eg.fillRect(x + 1, y + 4, cw - 2, ch - 8);
        // Blinds: some windows only glow in the lower half.
        if (r() < 0.25) {
          eg.globalAlpha = 1;
          eg.fillStyle = "#000";
          eg.fillRect(x + 1, y + 2, cw - 2, (ch - 4) * 0.45);
        }
      }
    }
  }
  eg.globalAlpha = 1;
  ag.fillStyle = "#05080f";
  ag.fillRect(0, 0, 2, 2);
  return { map: texture(a, true, true), emissive: texture(e, true, true) };
}

/** Wet asphalt: dark albedo with tar patches and faint aggregate speckle; tiles every 200 units. */
export function asphaltTexture(): THREE.Texture {
  const [c, g] = canvas(512, 512);
  const r = rng(7);
  g.fillStyle = "#171b24";
  g.fillRect(0, 0, 512, 512);
  for (let i = 0; i < 90; i++) {
    const x = r() * 512;
    const y = r() * 512;
    const rad = 20 + r() * 90;
    const grad = g.createRadialGradient(x, y, 0, x, y, rad);
    const dark = r() < 0.6;
    grad.addColorStop(0, dark ? "rgba(6,8,14,0.55)" : "rgba(40,46,60,0.35)");
    grad.addColorStop(1, "rgba(0,0,0,0)");
    g.fillStyle = grad;
    g.fillRect(x - rad, y - rad, rad * 2, rad * 2);
  }
  for (let i = 0; i < 9000; i++) {
    const v = 30 + Math.floor(r() * 50);
    g.fillStyle = `rgba(${v},${v + 4},${v + 12},${0.25 + r() * 0.4})`;
    g.fillRect(r() * 512, r() * 512, 1, 1);
  }
  return texture(c, true, true);
}

/** Wetness: bright = rough/dry, dark = puddle. Read from the G channel as a roughness map. */
export function wetnessTexture(): THREE.Texture {
  const [c, g] = canvas(256, 256);
  const r = rng(11);
  g.fillStyle = "rgb(150,150,150)";
  g.fillRect(0, 0, 256, 256);
  for (let i = 0; i < 40; i++) {
    const x = r() * 256;
    const y = r() * 256;
    const rad = 10 + r() * 50;
    const grad = g.createRadialGradient(x, y, 0, x, y, rad);
    grad.addColorStop(0, "rgba(20,20,20,0.9)");
    grad.addColorStop(1, "rgba(20,20,20,0)");
    g.fillStyle = grad;
    g.fillRect(x - rad, y - rad, rad * 2, rad * 2);
  }
  return texture(c, false, true);
}

/** City ground between roads: dark paving with a faint block grid. Tiles every 400 units. */
export function groundTexture(): THREE.Texture {
  const [c, g] = canvas(512, 512);
  const r = rng(3);
  g.fillStyle = "#0b0f1a";
  g.fillRect(0, 0, 512, 512);
  for (let i = 0; i < 4000; i++) {
    const v = 14 + Math.floor(r() * 16);
    g.fillStyle = `rgba(${v},${v + 3},${v + 12},0.6)`;
    g.fillRect(r() * 512, r() * 512, 2, 2);
  }
  g.strokeStyle = "rgba(90,120,200,0.10)";
  g.lineWidth = 2;
  for (let i = 0; i <= 512; i += 64) {
    g.beginPath();
    g.moveTo(i, 0);
    g.lineTo(i, 512);
    g.moveTo(0, i);
    g.lineTo(512, i);
    g.stroke();
  }
  return texture(c, true, true);
}

/** Soft round falloff, used for light pools, beacons and haze. */
export function glowTexture(): THREE.Texture {
  const [c, g] = canvas(128, 128);
  const grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  grad.addColorStop(0, "rgba(255,255,255,1)");
  grad.addColorStop(0.25, "rgba(255,255,255,0.55)");
  grad.addColorStop(0.6, "rgba(255,255,255,0.12)");
  grad.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grad;
  g.fillRect(0, 0, 128, 128);
  return texture(c, false);
}

/** Road chevron pointing +U. */
export function arrowTexture(): THREE.Texture {
  const [c, g] = canvas(128, 256);
  g.clearRect(0, 0, 128, 256);
  g.fillStyle = "#fff";
  for (let k = 0; k < 2; k++) {
    const y = 40 + k * 90;
    g.beginPath();
    g.moveTo(64, y);
    g.lineTo(118, y + 60);
    g.lineTo(96, y + 60);
    g.lineTo(64, y + 26);
    g.lineTo(32, y + 60);
    g.lineTo(10, y + 60);
    g.closePath();
    g.fill();
  }
  return texture(c, false);
}

const AD_TEXT = ["NEON//NET", "パケット", "SYNAPSE", "DATA·HAUS", "ネオン", "V-CORE", "HYPERLINK", "東京 NET", "KERNEL", "0xCAFE"];
const AD_COLORS: [string, string][] = [
  ["#ff2ea6", "#5b1bff"],
  ["#00e5ff", "#0040ff"],
  ["#ffb020", "#ff2e6a"],
  ["#4dffc3", "#0077ff"],
  ["#b48cff", "#ff2ea6"],
];

/** Holographic billboard artwork: gradient panel, big glyphs, scan lines. */
export function adTexture(seed: number): THREE.Texture {
  const [c, g] = canvas(512, 256);
  const r = rng(seed * 97 + 13);
  const [c1, c2] = AD_COLORS[Math.floor(r() * AD_COLORS.length)]!;
  const grad = g.createLinearGradient(0, 0, 512, 256);
  grad.addColorStop(0, c1);
  grad.addColorStop(1, c2);
  g.fillStyle = "rgba(0,0,0,1)";
  g.fillRect(0, 0, 512, 256);
  g.globalAlpha = 0.35;
  g.fillStyle = grad;
  g.fillRect(0, 0, 512, 256);
  g.globalAlpha = 1;
  g.strokeStyle = c1;
  g.lineWidth = 8;
  g.strokeRect(8, 8, 496, 240);
  g.font = "900 92px 'Segoe UI', 'Yu Gothic UI', 'Meiryo', sans-serif";
  g.textAlign = "center";
  g.textBaseline = "middle";
  g.shadowColor = c1;
  g.shadowBlur = 24;
  g.fillStyle = "#ffffff";
  g.fillText(AD_TEXT[Math.floor(r() * AD_TEXT.length)]!, 256, 118);
  g.shadowBlur = 0;
  g.font = "600 26px 'Consolas', monospace";
  g.fillStyle = c1;
  g.fillText(`// ${Math.floor(r() * 9999).toString().padStart(4, "0")} · ONLINE`, 256, 206);
  g.fillStyle = "rgba(0,0,0,0.35)";
  for (let y = 0; y < 256; y += 4) g.fillRect(0, y, 512, 1);
  return texture(c);
}
