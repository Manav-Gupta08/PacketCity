// Regenerates core/data/oui.tsv (MAC prefix -> vendor) from the public IEEE MA-L registry.
// Usage: node scripts/generate-oui.mjs [path/to/oui.csv]   (downloads the registry if no path)
import { readFileSync, writeFileSync } from "node:fs";

const SOURCE = "https://standards-oui.ieee.org/oui/oui.csv";
const OUT = new URL("../core/data/oui.tsv", import.meta.url);
// The registry rejects non-browser user agents.
const HEADERS = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36" };
const MAX_NAME = 32;

function parseCsvLine(line) {
  const cells = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { cells.push(cur); cur = ""; }
    else cur += ch;
  }
  cells.push(cur);
  return cells;
}

const SUFFIX = /[\s,.]+(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|s\.a|srl|bv|b\.v|nv|oy|ab|as|a\/s|plc|pte|pty|kk|k\.k|spa|s\.p\.a|sas|technologies|technology|electronics|electronic|international|holdings)\.?$/i;

function shorten(name) {
  let n = name.replace(/\s+/g, " ").trim();
  for (let prev = ""; prev !== n; ) {
    prev = n;
    n = n.replace(SUFFIX, "").replace(/[\s,.(]+$/, "").trim();
  }
  if (!n) n = name.trim();
  return n.length > MAX_NAME ? `${n.slice(0, MAX_NAME - 1).trim()}…` : n;
}

const text = process.argv[2] ? readFileSync(process.argv[2], "utf8") : await (await fetch(SOURCE, { headers: HEADERS })).text();
const rows = new Map();
for (const line of text.split(/\r?\n/).slice(1)) {
  if (!line.trim()) continue;
  const [registry, assignment, org] = parseCsvLine(line);
  if (registry !== "MA-L" || !/^[0-9A-F]{6}$/.test(assignment) || !org) continue;
  rows.set(assignment, shorten(org).replace(/\t/g, " "));
}
const out = [...rows].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}\t${v}`).join("\n") + "\n";
writeFileSync(OUT, out);
console.log(`wrote ${rows.size} prefixes (${out.length} bytes) to ${OUT.pathname}`);
