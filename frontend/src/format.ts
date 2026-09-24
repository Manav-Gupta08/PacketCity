const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"];

export function formatBytes(bytes: number): string {
  let v = bytes;
  let u = 0;
  while (v >= 1024 && u < BYTE_UNITS.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v >= 100 || u === 0 ? Math.round(v) : v.toFixed(1)} ${BYTE_UNITS[u]}`;
}

export const formatRate = (bytesPerSec: number): string => `${formatBytes(bytesPerSec)}/s`;

const BIT_UNITS = ["bps", "Kbps", "Mbps", "Gbps"];

/** Network throughput convention: decimal bits per second. */
export function formatBitRate(bytesPerSec: number): string {
  let v = bytesPerSec * 8;
  let u = 0;
  while (v >= 1000 && u < BIT_UNITS.length - 1) {
    v /= 1000;
    u++;
  }
  return `${v >= 100 || u === 0 ? Math.round(v) : v.toFixed(1)} ${BIT_UNITS[u]}`;
}

export function formatCount(n: number): string {
  if (n < 1000) return String(Math.round(n));
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

export function formatTimestamp(us: number): string {
  const d = new Date(us / 1000);
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${Math.round(s % 60)}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

export const hex = (n: number, width = 4): string => `0x${n.toString(16).padStart(width, "0")}`;

const HEX_ROW = 16;

/** Classic offset · hex · ASCII dump; non-printable bytes show as ".". */
export function hexDump(bytes: ArrayLike<number>): string {
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += HEX_ROW) {
    const row = Array.from({ length: Math.min(HEX_ROW, bytes.length - off) }, (_, i) => bytes[off + i]!);
    const hexPart = row.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${off.toString(16).padStart(4, "0")}  ${hexPart.padEnd(HEX_ROW * 3 - 1)}  ${ascii}`);
  }
  return lines.join("\n");
}
