import { useMemo } from "react";

import { formatBytes, formatCount } from "../format";
import { setApp, useApp } from "../stores/appStore";
import { TRAFFIC_CLASSES, type AppProtocol, type TrafficClass } from "../types";
import { cssColor, VEHICLE_STYLES } from "../visualization/vehicleStyles";

const CLASS_INFO: Record<TrafficClass, string> = {
  https: "Encrypted web and app traffic (TLS on any port, QUIC on UDP 443).",
  http: "Unencrypted HTTP/1.x: method, host and path are visible on the network.",
  tcp: "Other TCP connections (SSH, databases, proprietary protocols…).",
  udp: "Other UDP datagrams (games, VoIP, streaming, discovery…).",
  dns: "Name lookups: DNS, multicast DNS (.local) and LLMNR.",
  icmp: "Control messages: ping, unreachable, IPv6 neighbour discovery.",
  arp: "IPv4 address-to-MAC resolution on the local segment.",
  dhcp: "Address assignment (DHCPv4 and DHCPv6).",
  other: "Traffic PacketCity does not classify further.",
};

const APP_LABEL: Record<AppProtocol, string> = {
  dns: "DNS", mdns: "mDNS", llmnr: "LLMNR", dhcp: "DHCP", dhcpv6: "DHCPv6", http: "HTTP", tls: "TLS",
  quic: "QUIC", ntp: "NTP", ssdp: "SSDP", ssh: "SSH", nbns: "NetBIOS names", unknown: "Unidentified",
};

function hideOnly(cls: TrafficClass) {
  setApp({ vizFilter: TRAFFIC_CLASSES.filter((c) => c !== cls).map((c) => `!class:${c}`).join(" "), view: "global" });
}

export function ProtocolsView() {
  const stats = useApp((s) => s.stats);
  const flows = useApp((s) => s.flows);
  const total = stats ? TRAFFIC_CLASSES.reduce((sum, c) => sum + (stats.classTotals[c] ?? 0), 0) : 0;

  const apps = useMemo(() => {
    const m = new Map<AppProtocol, { flows: number; bytes: number }>();
    for (const f of flows) {
      const e = m.get(f.app) ?? { flows: 0, bytes: 0 };
      e.flows += 1;
      e.bytes += f.bytes;
      m.set(f.app, e);
    }
    return [...m.entries()].sort((a, b) => b[1].bytes - a[1].bytes);
  }, [flows]);

  return (
    <section className="page glass" aria-label="Protocols">
      <header className="page__head">
        <h3>Protocols</h3>
        <span className="muted">Traffic classes as drawn on the map, with totals since the session started.</span>
      </header>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Class</th>
              <th className="num">Packets</th>
              <th className="num">Share</th>
              <th className="num">Now (pkt/s)</th>
              <th>What it is</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {TRAFFIC_CLASSES.map((c) => {
              const n = stats?.classTotals[c] ?? 0;
              const s = VEHICLE_STYLES[c];
              return (
                <tr key={c}>
                  <td>
                    <i className={`legend__swatch legend__swatch--${s.shape}`} style={{ background: cssColor(s.color) }} /> {s.label}
                  </td>
                  <td className="num mono">{n.toLocaleString()}</td>
                  <td className="num mono">{total ? `${((n / total) * 100).toFixed(1)}%` : "—"}</td>
                  <td className="num mono">{formatCount(stats?.classRates[c] ?? 0)}</td>
                  <td className="muted wrap">{CLASS_INFO[c]}</td>
                  <td>
                    <button className="btn btn--glass btn--sm" onClick={() => hideOnly(c)} title="Show only this class on the map">
                      Isolate
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <h4 className="page__sub">Application protocols in active connections</h4>
      <div className="app-protos">
        {apps.length === 0 && <p className="muted">No active connections.</p>}
        {apps.map(([app, v]) => (
          <div key={app} className="app-proto">
            <span className="app-proto__name">{APP_LABEL[app]}</span>
            <span className="mono">{v.flows} flows</span>
            <span className="mono muted">{formatBytes(v.bytes)}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
