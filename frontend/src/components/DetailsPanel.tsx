import { useEffect, useState, type ReactNode } from "react";

import { formatBytes, formatDuration, formatTimestamp, hex } from "../format";
import { api, toCommandError } from "../services/ipc";
import { clearSelection } from "../services/session";
import { setApp, useApp } from "../stores/appStore";
import type { DeviceSnapshot, FlowSnapshot, PacketRecord } from "../types";
import { internetHostnames } from "../visualization/destinations";
import { cssColor, VEHICLE_STYLES } from "../visualization/vehicleStyles";
import { HexSection } from "./HexView";
import { Icon } from "./Icon";

const FLOW_REFRESH_MS = 1000;

type Row = [label: string, value: ReactNode];

function Rows({ rows }: { rows: Row[] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k} className="kv__row">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Section({ title, open = false, children }: { title: string; open?: boolean; children: ReactNode }) {
  return (
    <details className="details__section" open={open}>
      <summary>{title}</summary>
      {children}
    </details>
  );
}

const endpoint = (ip: string | undefined, port: number | undefined) =>
  ip === undefined ? "—" : port === undefined ? ip : ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;

const Badge = ({ cls }: { cls: PacketRecord["class"] }) => (
  <span className="badge" style={{ color: cssColor(VEHICLE_STYLES[cls].color), borderColor: cssColor(VEHICLE_STYLES[cls].color) }}>
    {VEHICLE_STYLES[cls].label}
  </span>
);

function PacketDetails({ p }: { p: PacketRecord }) {
  const srcPort = p.tcp?.srcPort ?? p.udp?.srcPort;
  const dstPort = p.tcp?.dstPort ?? p.udp?.dstPort;
  const src = p.ip?.src ?? p.arp?.senderIp ?? p.ethernet?.src;
  const dst = p.ip?.dst ?? p.arp?.targetIp ?? p.ethernet?.dst;

  return (
    <>
      <h3 className="details__title">Packet Details <span className="mono muted">#{p.id}</span></h3>
      <Rows
        rows={[
          ["Time", <span className="mono">{formatTimestamp(p.timestampUs)}</span>],
          ["Direction", <b className={`dir dir--${p.direction}`}>{p.direction.toUpperCase()}</b>],
          ["Source", <span className="mono">{endpoint(src, srcPort)}</span>],
          ["Destination", <span className="mono">{endpoint(dst, dstPort)}</span>],
          ["Protocol", <><Badge cls={p.class} /> <span className="muted">{p.transport.toUpperCase()}{p.app !== "unknown" ? ` · ${p.app.toUpperCase()}` : ""}</span></>],
          ["Length", `${p.wireLen.toLocaleString()} bytes`],
          ...(p.tcp ? ([["Flags", p.tcp.flags.join(", ") || "none"]] as Row[]) : []),
          ...(p.ip ? ([["TTL", p.ip.ttl]] as Row[]) : []),
        ]}
      />
      {p.issue && <p className="details__issue">Malformed at {p.issue.layer} layer: {p.issue.reason}</p>}

      {(p.dns || p.tls || p.http || p.dhcp || p.netbios) && (
        <Section title="Application" open>
          {p.http && (
            <pre className="details__code mono">
              {p.http.method ? `${p.http.method} ${p.http.path ?? ""}` : `${p.http.version ?? "HTTP"} ${p.http.status ?? ""}`}
              {p.http.host ? `\nHost: ${p.http.host}` : ""}
            </pre>
          )}
          {p.dns && (
            <Rows
              rows={[
                ["DNS", p.dns.isResponse ? "Response" : "Query"],
                ["Name", <span className="mono">{p.dns.queryName ?? "—"}</span>],
                ["Type", p.dns.queryTypeName ?? "—"],
                ["Answers", p.dns.answerCount],
                ...(p.dns.answers.length
                  ? ([["Addresses", <span className="mono wrap">{p.dns.answers.map((a) => a.address).join(", ")}</span>]] as Row[])
                  : []),
              ]}
            />
          )}
          {p.dhcp && (
            <Rows
              rows={[
                ["DHCP", p.dhcp.messageTypeName ?? "—"],
                ["Client MAC", <span className="mono">{p.dhcp.clientMac ?? "—"}</span>],
                ...(p.dhcp.hostname ? ([["Host name", <span className="mono">{p.dhcp.hostname}</span>]] as Row[]) : []),
                ...(p.dhcp.requestedIp ? ([["Requested IP", <span className="mono">{p.dhcp.requestedIp}</span>]] as Row[]) : []),
                ...(p.dhcp.yourIp ? ([["Assigned IP", <span className="mono">{p.dhcp.yourIp}</span>]] as Row[]) : []),
              ]}
            />
          )}
          {p.netbios && (
            <Rows
              rows={[
                ["NetBIOS", `${p.netbios.opcodeName}${p.netbios.isResponse ? " response" : ""}`],
                ["Name", <span className="mono">{p.netbios.name ?? "—"}{p.netbios.group ? " (group)" : ""}</span>],
                ...(p.netbios.address ? ([["Address", <span className="mono">{p.netbios.address}</span>]] as Row[]) : []),
              ]}
            />
          )}
          {p.tls && (
            <Rows
              rows={[
                ["TLS record", p.tls.contentTypeName],
                ["Handshake", p.tls.handshakeType === 1 ? "ClientHello" : (p.tls.handshakeType ?? "—")],
                ["Server name", <span className="mono">{p.tls.sni ?? "—"}</span>],
              ]}
            />
          )}
          <p className="details__note">Payload contents are never stored; query strings are dropped.</p>
        </Section>
      )}
      {p.ethernet && (
        <Section title="Ethernet">
          <Rows
            rows={[
              ["Source MAC", <span className="mono">{p.ethernet.src}</span>],
              ["Destination MAC", <span className="mono">{p.ethernet.dst}</span>],
              ["EtherType", <span className="mono">{hex(p.ethernet.etherType)}</span>],
              ["VLAN", p.ethernet.vlan ?? "—"],
              ["Cast", p.cast],
            ]}
          />
        </Section>
      )}
      {p.arp && (
        <Section title="ARP" open>
          <Rows
            rows={[
              ["Operation", p.arp.operation === 1 ? "Request" : p.arp.operation === 2 ? "Reply" : p.arp.operation],
              ["Sender", <span className="mono">{`${p.arp.senderIp} (${p.arp.senderMac})`}</span>],
              ["Target", <span className="mono">{`${p.arp.targetIp} (${p.arp.targetMac})`}</span>],
            ]}
          />
        </Section>
      )}
      {p.ip && (
        <Section title={p.ip.version === 4 ? "IPv4" : "IPv6"}>
          <Rows
            rows={[
              [p.ip.version === 4 ? "TTL" : "Hop limit", p.ip.ttl],
              ["Protocol", p.ip.protocol],
              ["Header / total", `${p.ip.headerLen} / ${p.ip.totalLen} bytes`],
              ["DSCP / ECN", `${p.ip.dscp} / ${p.ip.ecn}`],
              ...(p.ip.version === 4
                ? ([
                    ["Identification", p.ip.identification !== null ? hex(p.ip.identification) : "—"],
                    ["Flags", [p.ip.dontFragment && "DF", p.ip.moreFragments && "MF"].filter(Boolean).join(", ") || "none"],
                    ["Fragment offset", p.ip.fragmentOffset],
                  ] as Row[])
                : ([["Flow label", p.ip.flowLabel !== null ? hex(p.ip.flowLabel, 5) : "—"]] as Row[])),
            ]}
          />
        </Section>
      )}
      {p.tcp && (
        <Section title="TCP">
          <Rows
            rows={[
              ["Ports", `${p.tcp.srcPort} → ${p.tcp.dstPort}`],
              ["Sequence", <span className="mono">{p.tcp.seq}</span>],
              ["Acknowledgement", <span className="mono">{p.tcp.ack}</span>],
              ["Window", p.tcp.window],
              ["Payload", `${p.tcp.payloadLen} bytes`],
            ]}
          />
        </Section>
      )}
      {p.udp && (
        <Section title="UDP">
          <Rows rows={[["Ports", `${p.udp.srcPort} → ${p.udp.dstPort}`], ["Length", `${p.udp.length} bytes`], ["Payload", `${p.udp.payloadLen} bytes`]]} />
        </Section>
      )}
      {p.icmp && (
        <Section title={p.icmp.version === 4 ? "ICMP" : "ICMPv6"} open>
          <Rows rows={[["Type", `${p.icmp.icmpType} · ${p.icmp.description}`], ["Code", p.icmp.code]]} />
        </Section>
      )}
      <Section title="Metadata">
        <Rows rows={[["Captured", `${p.capturedLen} of ${p.wireLen} bytes`], ["Network", p.network], ["Flow", p.flowId ?? "—"]]} />
      </Section>
      <HexSection id={p.id} />
    </>
  );
}

function FlowDetails({ f, compact }: { f: FlowSnapshot; compact: boolean }) {
  const focusFlowId = useApp((s) => s.focusFlowId);
  return (
    <div className="details__flow">
      {!compact && <h3 className="details__title">Connection <span className="mono muted">FLOW-{String(f.id).padStart(5, "0")}</span></h3>}
      {compact && <div className="panel-title">CONNECTION · FLOW-{String(f.id).padStart(5, "0")}</div>}
      <Rows
        rows={[
          ["Protocol", <><Badge cls={f.class} /> <span className="muted">{f.protocol}</span></>],
          ["Initiator", <span className="mono">{f.initiator}</span>],
          ["Responder", <span className="mono">{f.responder}</span>],
          ...(f.hostname
            ? ([
                [
                  "Host",
                  <>
                    <span className="mono">{f.hostname}</span>
                    {f.hostnameSource === "dnsAnswer" && <span className="muted" title="Inferred: this address was returned by an earlier DNS lookup"> · via DNS</span>}
                  </>,
                ],
              ] as Row[])
            : []),
          ["Packets", `${f.packets.toLocaleString()} (${f.packetsFwd} → / ← ${f.packetsRev})`],
          ["Upload / download", `${formatBytes(f.bytesOut)} / ${formatBytes(f.bytesIn)}`],
          ["Duration", formatDuration(f.durationMs)],
          ["Rate / avg size", `${f.packetRate.toFixed(1)} pkt/s · ${Math.round(f.avgPacketSize)} B`],
          ...(f.tcp
            ? ([
                ["TCP state", `${f.tcp.state}${f.tcp.midstream ? " (joined mid-stream)" : ""}`],
                ["Retransmissions", f.tcp.retransmissions],
              ] as Row[])
            : []),
        ]}
      />
      <button className="btn btn--glass btn--block" onClick={() => setApp({ focusFlowId: focusFlowId === f.id ? null : f.id })}>
        {focusFlowId === f.id ? "Stop following" : "Follow Connection →"}
      </button>
    </div>
  );
}

const ROLE_LABEL: Record<DeviceSnapshot["role"], string> = { thisHost: "This device", gateway: "Gateway / router", lan: "LAN device" };
const NAME_SOURCE: Record<NonNullable<DeviceSnapshot["hostnameSource"]>, string> = {
  dhcp: "DHCP",
  mdns: "mDNS",
  llmnr: "LLMNR",
  netbios: "NetBIOS",
};

function NodeDetails({ node, devices, flows }: { node: string; devices: DeviceSnapshot[]; flows: FlowSnapshot[] }) {
  const d = devices.find((x) => x.node === node);
  if (node === "internet" || node === "broadcast" || node === "lan") {
    const title = node === "internet" ? "Internet" : node === "broadcast" ? "LAN broadcast" : "Other LAN devices";
    const text =
      node === "internet"
        ? "Everything outside this network's subnets, reached through the gateway."
        : node === "broadcast"
          ? "Broadcast and multicast destinations: ARP, DHCP, mDNS, SSDP and similar discovery traffic."
          : "LAN devices beyond the number shown as buildings.";
    const related = node === "internet" ? internetHostnames(flows).slice(0, 8) : [];
    return (
      <>
        <h3 className="details__title">{title}</h3>
        <p className="muted">{text}</p>
        {related.length > 0 && (
          <Section title="Recent destinations" open>
            <ul className="details__list mono">
              {related.map((f) => (
                <li key={f.id}>{f.hostname}</li>
              ))}
            </ul>
          </Section>
        )}
      </>
    );
  }
  if (!d && node === "gateway") {
    return (
      <>
        <h3 className="details__title">Router / gateway</h3>
        <p className="muted">
          Not identified yet. The gateway is learned from the MAC address that this machine's internet-bound traffic is sent to.
        </p>
      </>
    );
  }
  if (!d) return <p className="muted">This device is no longer tracked.</p>;
  const primaryIp = d.ips.find((ip) => !ip.includes(":")) ?? d.ips[0];
  return (
    <>
      <h3 className="details__title">{ROLE_LABEL[d.role]}</h3>
      <Rows
        rows={[
          ...(d.hostname
            ? ([["Name", <><span className="mono">{d.hostname}</span> <span className="muted">· via {NAME_SOURCE[d.hostnameSource ?? "dhcp"]}</span></>]] as Row[])
            : []),
          ["Address", <span className="mono">{d.ips.join(", ") || "—"}</span>],
          ["MAC", <span className="mono">{d.mac ?? "—"}</span>],
          ...(d.vendor ? ([["Vendor", d.vendor]] as Row[]) : []),
          ["Sent", `${d.packetsSent.toLocaleString()} pkts · ${formatBytes(d.bytesSent)}`],
          ["Received", `${d.packetsReceived.toLocaleString()} pkts · ${formatBytes(d.bytesReceived)}`],
          ...(d.firstSeenUs ? ([["First seen", <span className="mono">{formatTimestamp(d.firstSeenUs)}</span>]] as Row[]) : []),
          ["Last seen", <span className="mono">{d.lastSeenUs ? formatTimestamp(d.lastSeenUs) : "—"}</span>],
        ]}
      />
      {primaryIp && d.role !== "thisHost" && (
        <button className="btn btn--glass btn--block" onClick={() => setApp({ vizFilter: `ip:${primaryIp}` })}>
          Show only this device's traffic
        </button>
      )}
    </>
  );
}

export function DetailsPanel() {
  const selection = useApp((s) => s.selection);
  const sessionId = useApp((s) => s.session?.id);
  const devices = useApp((s) => s.devices);
  const flows = useApp((s) => s.flows);
  const [packet, setPacket] = useState<PacketRecord | null | undefined>(undefined);
  const [flow, setFlow] = useState<FlowSnapshot | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setPacket(undefined);
    setError(null);
    if (selection.packetId === null) return;
    let cancelled = false;
    api
      .getPacket(selection.packetId)
      .then((p) => !cancelled && setPacket(p))
      .catch((e: unknown) => !cancelled && setError(toCommandError(e).message));
    return () => {
      cancelled = true;
    };
  }, [selection.packetId, sessionId]);

  useEffect(() => {
    setFlow(undefined);
    const id = selection.flowId;
    if (id === null) return;
    let cancelled = false;
    const load = () =>
      api
        .getFlow(id)
        .then((f) => !cancelled && setFlow(f))
        .catch((e: unknown) => !cancelled && setError(toCommandError(e).message));
    load();
    const timer = window.setInterval(load, FLOW_REFRESH_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selection.flowId, sessionId]);

  if (selection.packetId === null && selection.flowId === null && selection.node === null) return null;

  return (
    <aside className="details glass" aria-label="Details">
      <button className="details__close" onClick={clearSelection} aria-label="Close details">
        <Icon name="close" size={16} />
      </button>
      {error && <p className="details__issue">{error}</p>}
      {selection.packetId !== null && packet === null && (
        <p className="muted">Packet #{selection.packetId} is no longer retained (the inspector keeps the most recent packets).</p>
      )}
      {packet && <PacketDetails p={packet} />}
      {selection.flowId !== null && flow === null && <p className="muted">This connection has expired.</p>}
      {flow && <FlowDetails f={flow} compact={selection.packetId !== null} />}
      {selection.node && <NodeDetails node={selection.node} devices={devices} flows={flows} />}
    </aside>
  );
}
