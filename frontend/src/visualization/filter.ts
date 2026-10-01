import type { TrafficEvent } from "../types";

/**
 * Visualization filter (client-side; never restarts capture). Grammar: whitespace-separated terms.
 * Terms with the same key are OR'ed, different keys are AND'ed; prefix `!` or `-` negates.
 *
 *   tcp udp icmp            transport
 *   dns https http arp dhcp traffic class      class:tcp  exact visual class (legend toggles)
 *   port:443  ip:10.0.0.5  ip:192.168.*  host:example  direction:in|out  flow:12
 *   threat                  packets flagged hostile (alias: malicious)
 */
type Key = "transport" | "class" | "port" | "ip" | "host" | "direction" | "flow" | "threat";

interface Term {
  key: Key;
  value: string;
  negate: boolean;
}

export interface ParsedFilter {
  terms: Term[];
  errors: string[];
}

const TRANSPORT_WORDS = new Set(["tcp", "udp", "icmp"]);
const CLASS_WORDS = new Set(["dns", "https", "http", "arp", "dhcp", "other"]);
const DIRECTIONS: Record<string, string> = {
  in: "incoming",
  incoming: "incoming",
  out: "outgoing",
  outgoing: "outgoing",
  local: "local",
  transit: "transit",
};

export function parseFilter(input: string): ParsedFilter {
  const terms: Term[] = [];
  const errors: string[] = [];
  for (const raw of input.trim().toLowerCase().split(/\s+/).filter(Boolean)) {
    const negate = raw.startsWith("!") || raw.startsWith("-");
    const word = negate ? raw.slice(1) : raw;
    const colon = word.indexOf(":");
    if (colon < 0) {
      if (TRANSPORT_WORDS.has(word)) terms.push({ key: "transport", value: word, negate });
      else if (CLASS_WORDS.has(word)) terms.push({ key: "class", value: word, negate });
      else if (word === "threat" || word === "malicious") terms.push({ key: "threat", value: "", negate });
      else errors.push(`Unknown term "${raw}"`);
      continue;
    }
    const k = word.slice(0, colon);
    const v = word.slice(colon + 1);
    if (!v) {
      errors.push(`Missing value in "${raw}"`);
    } else if (k === "port" && /^\d{1,5}$/.test(v) && Number(v) <= 65535) {
      terms.push({ key: "port", value: v, negate });
    } else if (k === "ip" || k === "host") {
      terms.push({ key: k, value: v, negate });
    } else if (k === "class" && (CLASS_WORDS.has(v) || TRANSPORT_WORDS.has(v))) {
      terms.push({ key: "class", value: v, negate });
    } else if (k === "direction" && DIRECTIONS[v]) {
      terms.push({ key: "direction", value: DIRECTIONS[v]!, negate });
    } else if (k === "flow" && /^\d+$/.test(v)) {
      terms.push({ key: "flow", value: v, negate });
    } else {
      errors.push(`Invalid term "${raw}"`);
    }
  }
  return { terms, errors };
}

function ipMatches(pattern: string, ip: string): boolean {
  return pattern.endsWith("*") ? ip.startsWith(pattern.slice(0, -1)) : ip === pattern;
}

function termMatches(t: Term, e: TrafficEvent): boolean {
  switch (t.key) {
    case "transport":
      return t.value === "icmp" ? e.transport === "icmp" || e.transport === "icmpv6" : e.transport === t.value;
    case "class":
      return e.class === t.value;
    case "port":
      return String(e.srcPort) === t.value || String(e.dstPort) === t.value;
    case "ip":
      return ipMatches(t.value, e.src) || ipMatches(t.value, e.dst);
    case "host":
      return (e.host ?? "").toLowerCase().includes(t.value);
    case "direction":
      return e.direction === t.value;
    case "flow":
      return String(e.flowId) === t.value;
    case "threat":
      return e.threat !== null;
  }
}

export function compileFilter(parsed: ParsedFilter): (e: TrafficEvent) => boolean {
  if (parsed.terms.length === 0) return () => true;
  const positive = new Map<Key, Term[]>();
  const negative: Term[] = [];
  for (const t of parsed.terms) {
    if (t.negate) negative.push(t);
    else positive.set(t.key, [...(positive.get(t.key) ?? []), t]);
  }
  const groups = [...positive.values()];
  return (e) => groups.every((g) => g.some((t) => termMatches(t, e))) && !negative.some((t) => termMatches(t, e));
}
