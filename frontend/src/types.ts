// Mirrors the serde output of packetcity-core / packetcity-capture / desktop. Keep in sync.

export type Direction = "incoming" | "outgoing" | "local" | "transit";
export type Cast = "unicast" | "broadcast" | "multicast";
export type TrafficClass = "tcp" | "udp" | "dns" | "https" | "http" | "icmp" | "arp" | "dhcp" | "other";
export type TransportProtocol = "tcp" | "udp" | "icmp" | "icmpv6" | "unknown" | "none";
export type NetworkProtocol = "ipv4" | "ipv6" | "arp" | "unknown";
export type AppProtocol =
  | "dns" | "mdns" | "llmnr" | "dhcp" | "dhcpv6" | "http" | "tls" | "quic" | "ntp" | "ssdp" | "ssh" | "nbns" | "unknown";
export type LinkType = "ethernet" | "null" | "loop" | "rawIp" | "linuxSll";

export const TRAFFIC_CLASSES: readonly TrafficClass[] = [
  "https", "http", "tcp", "udp", "dns", "icmp", "arp", "dhcp", "other",
];

export interface TrafficEvent {
  packetId: number;
  flowId: number | null;
  timestampUs: number;
  direction: Direction;
  cast: Cast;
  class: TrafficClass;
  transport: TransportProtocol;
  /** Map nodes: "self" | "gateway" | "internet" | "broadcast" | "lan" | "dev:<id>". */
  srcNode: string;
  dstNode: string;
  src: string;
  dst: string;
  srcPort: number | null;
  dstPort: number | null;
  host: string | null;
  length: number;
  packets: number;
  bytes: number;
}

export interface TcpTracker {
  state: "synSent" | "synReceived" | "established" | "closing" | "closed" | "reset";
  midstream: boolean;
  retransmissions: number;
}

export interface FlowSnapshot {
  id: number;
  protocol: string;
  initiator: string;
  responder: string;
  direction: Direction;
  class: TrafficClass;
  app: AppProtocol;
  hostname: string | null;
  /** "dnsAnswer" means the name was inferred from an earlier DNS response for this address. */
  hostnameSource: "inBand" | "dnsAnswer" | null;
  firstSeenUs: number;
  lastSeenUs: number;
  durationMs: number;
  packets: number;
  bytes: number;
  packetsFwd: number;
  packetsRev: number;
  bytesFwd: number;
  bytesRev: number;
  bytesOut: number;
  bytesIn: number;
  packetRate: number;
  avgPacketSize: number;
  tcp: TcpTracker | null;
}

export interface StatsSnapshot {
  timestampUs: number;
  packetsPerSec: number;
  bytesPerSec: number;
  downloadBytesPerSec: number;
  uploadBytesPerSec: number;
  totalPackets: number;
  totalBytes: number;
  totalBytesIn: number;
  totalBytesOut: number;
  malformedPackets: number;
  classTotals: Record<TrafficClass, number>;
  classRates: Record<TrafficClass, number>;
  historyPackets: number[];
  historyBytes: number[];
  historyBytesIn: number[];
  historyBytesOut: number[];
  trackedFlows: number;
  activeFlows: number;
  activeConnections: number;
  activeDevices: number;
}

export type DeviceRole = "thisHost" | "gateway" | "lan";

export interface DeviceSnapshot {
  node: string;
  role: DeviceRole;
  /** Hostname when one was announced, else the primary IP. */
  label: string;
  hostname: string | null;
  hostnameSource: "netbios" | "llmnr" | "mdns" | "dhcp" | null;
  vendor: string | null;
  mac: string | null;
  ips: string[];
  packetsSent: number;
  packetsReceived: number;
  bytesSent: number;
  bytesReceived: number;
  firstSeenUs: number;
  lastSeenUs: number;
}

export interface PipelineHealth {
  framesDropped: number;
  /** Drops reported by the capture driver (kernel buffer full). */
  driverDropped: number;
  interfaceDropped: number;
  linkDown: boolean;
  queueDepth: number;
  meanLatencyMs: number;
}

export interface Alert {
  id: number;
  timestampUs: number;
  severity: "info" | "warning";
  kind: "duplicateIp" | "newDevice" | "portScan" | "hostSweep" | "retransmissions" | "malformedTraffic";
  title: string;
  detail: string;
  node: string | null;
  flowId: number | null;
}

export type StreamMessage =
  | { type: "traffic"; events: TrafficEvent[]; packets: number; aggregatedPackets: number }
  | { type: "stats"; stats: StatsSnapshot; health: PipelineHealth }
  | { type: "flows"; flows: FlowSnapshot[] }
  | { type: "devices"; devices: DeviceSnapshot[] }
  | { type: "alerts"; alerts: Alert[] }
  | { type: "sourceEnded"; reason: string; error: boolean };

export interface EthernetInfo { src: string; dst: string; etherType: number; vlan: number | null }
export interface ArpInfo { operation: number; senderMac: string; senderIp: string; targetMac: string; targetIp: string }
export interface IpInfo {
  version: 4 | 6;
  src: string;
  dst: string;
  ttl: number;
  protocol: number;
  headerLen: number;
  totalLen: number;
  dscp: number;
  ecn: number;
  identification: number | null;
  dontFragment: boolean;
  moreFragments: boolean;
  fragmentOffset: number;
  flowLabel: number | null;
}
export interface TcpInfo {
  srcPort: number; dstPort: number; seq: number; ack: number; flags: string[];
  window: number; headerLen: number; payloadLen: number;
}
export interface UdpInfo { srcPort: number; dstPort: number; length: number; payloadLen: number }
export interface IcmpInfo { version: number; icmpType: number; code: number; description: string }
export interface DnsInfo {
  transactionId: number; isResponse: boolean; opcode: number; rcode: number;
  questionCount: number; answerCount: number; queryName: string | null;
  queryType: number | null; queryTypeName: string | null; answers: { name: string; address: string; additional: boolean }[];
}
export interface DhcpInfo {
  messageType: number | null; messageTypeName: string | null; clientMac: string | null;
  hostname: string | null; requestedIp: string | null; yourIp: string | null;
}
export interface NetbiosInfo {
  isResponse: boolean; opcode: number; opcodeName: string; rcode: number;
  name: string | null; suffix: number | null; group: boolean; address: string | null;
}
export interface TlsInfo {
  contentType: number; contentTypeName: string; recordVersion: number;
  handshakeType: number | null; sni: string | null;
}
export interface HttpInfo {
  method: string | null; path: string | null; host: string | null; status: number | null; version: string | null;
}

export interface PacketRecord {
  id: number;
  flowId: number | null;
  timestampUs: number;
  direction: Direction;
  cast: Cast;
  class: TrafficClass;
  capturedLen: number;
  wireLen: number;
  network: NetworkProtocol;
  transport: TransportProtocol;
  app: AppProtocol;
  ethernet: EthernetInfo | null;
  arp: ArpInfo | null;
  ip: IpInfo | null;
  tcp: TcpInfo | null;
  udp: UdpInfo | null;
  icmp: IcmpInfo | null;
  dns: DnsInfo | null;
  dhcp: DhcpInfo | null;
  netbios: NetbiosInfo | null;
  tls: TlsInfo | null;
  http: HttpInfo | null;
  issue: { layer: string; reason: string } | null;
}

export type InterfaceKind = "ethernet" | "wireless" | "loopback" | "virtual" | "unknown";

export interface InterfaceInfo {
  id: string;
  displayName: string;
  description: string | null;
  kind: InterfaceKind;
  addresses: { address: string; netmask: string | null; broadcast: string | null }[];
  isUp: boolean;
  isRunning: boolean;
  connected: boolean | null;
}

export interface CaptureEnvironment {
  platform: string;
  driverAvailable: boolean;
  driverVersion: string | null;
  driverMessage: string | null;
  permissionHint: string;
}

export interface ReplayInfo {
  fileName: string;
  packets: number;
  bytes: number;
  firstUs: number;
  lastUs: number;
  skippedFrames: number;
  link: LinkType;
  inferredHost: string | null;
  inferredPrefix: number | null;
  prefixSource: "arp" | "assumed";
}

export interface ReplayStatus {
  positionUs: number;
  startUs: number;
  endUs: number;
  playing: boolean;
  speed: number;
  finished: boolean;
  generation: number;
}

export type ReplayCommand =
  | { action: "play" }
  | { action: "pause" }
  | { action: "speed"; value: number }
  | { action: "seek"; positionUs: number };

export interface SessionInfo {
  id: number;
  source: "live" | "demo" | "replay";
  interface: InterfaceInfo | null;
  link: LinkType;
  promiscuous: boolean;
  captureFilter: string | null;
  localAddresses: string[];
  startedAtUs: number;
  scope: { mode: string; visibility: string };
  replay: ReplayInfo | null;
}

export interface CommandError {
  code: string;
  message: string;
  hint: string | null;
}

export interface LiveCaptureOptions {
  interfaceId: string;
  promiscuous: boolean;
  captureFilter: string | null;
}
