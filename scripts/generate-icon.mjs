// Renders the app icon source (1024x1024 PNG) procedurally so no binary asset lives in the repo.
// Motif: two opposing neon lanes (incoming magenta / outgoing cyan) converging on a node.
import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";

const SIZE = 1024;
const px = Buffer.alloc(SIZE * SIZE * 4);

const clamp = (v) => Math.max(0, Math.min(255, Math.round(v)));
function blend(x, y, [r, g, b], a) {
  const i = (y * SIZE + x) * 4;
  px[i] = clamp(px[i] * (1 - a) + r * a);
  px[i + 1] = clamp(px[i + 1] * (1 - a) + g * a);
  px[i + 2] = clamp(px[i + 2] * (1 - a) + b * a);
  px[i + 3] = clamp(Math.max(px[i + 3], a * 255));
}

const CORNER = 220;
const inRoundedSquare = (x, y) => {
  const dx = Math.max(CORNER - x, x - (SIZE - 1 - CORNER), 0);
  const dy = Math.max(CORNER - y, y - (SIZE - 1 - CORNER), 0);
  return dx * dx + dy * dy <= CORNER * CORNER;
};

const CYAN = [0, 229, 255];
const MAGENTA = [255, 46, 166];
const lane = (y, cy, half) => Math.max(0, 1 - Math.abs(y - cy) / half);

for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    if (!inRoundedSquare(x, y)) continue;
    const t = y / SIZE;
    blend(x, y, [5 + 10 * t, 8 + 12 * t, 18 + 30 * t], 1);
    const inGlow = lane(y, 400, 90) ** 3 * 0.35;
    const outGlow = lane(y, 624, 90) ** 3 * 0.35;
    if (inGlow) blend(x, y, MAGENTA, inGlow);
    if (outGlow) blend(x, y, CYAN, outGlow);
    if (Math.abs(y - 400) < 18 && x > 150 && x < 874) blend(x, y, MAGENTA, 0.95);
    if (Math.abs(y - 624) < 18 && x > 150 && x < 874) blend(x, y, CYAN, 0.95);
    if (Math.abs(y - 512) < 4 && x > 170 && x < 854 && Math.floor(x / 40) % 2 === 0) blend(x, y, [200, 220, 255], 0.6);
    const d = Math.hypot(x - 512, y - 512);
    if (d < 70) blend(x, y, [235, 245, 255], 1);
    else if (d < 130) blend(x, y, CYAN, ((130 - d) / 60) ** 2 * 0.6);
  }
}

function crc32(buf) {
  let c = ~0;
  for (const b of buf) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8;
ihdr[9] = 6;
const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
for (let y = 0; y < SIZE; y++) px.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk("IHDR", ihdr),
  chunk("IDAT", deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);
mkdirSync(".deps", { recursive: true });
writeFileSync(".deps/icon-source.png", png);
console.log("wrote .deps/icon-source.png");
