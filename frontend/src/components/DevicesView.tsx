import { useDeferredValue, useMemo } from "react";

import { formatBytes, formatTimestamp } from "../format";
import { selectNode } from "../services/session";
import { useApp } from "../stores/appStore";
import type { DeviceSnapshot } from "../types";

const ROLE: Record<DeviceSnapshot["role"], string> = { thisHost: "This device", gateway: "Gateway", lan: "LAN" };

export function DevicesView() {
  const devices = useApp((s) => s.devices);
  const search = useApp((s) => s.search);
  const selected = useApp((s) => s.selection.node);
  const q = useDeferredValue(search.trim().toLowerCase());
  const rows = useMemo(
    () =>
      devices.filter(
        (d) => !q || `${d.label} ${d.hostname ?? ""} ${d.vendor ?? ""} ${d.ips.join(" ")} ${d.mac ?? ""} ${d.role}`.toLowerCase().includes(q),
      ),
    [devices, q],
  );

  return (
    <section className="table-view glass" aria-label="Devices">
      <div className="table-view__head">
        <h3>Devices</h3>
        <span className="muted">
          {rows.length} of {devices.length} · learned from traffic visible to this interface
        </span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Role</th>
              <th>Name</th>
              <th>Address</th>
              <th>MAC</th>
              <th>Vendor</th>
              <th className="num">Sent</th>
              <th className="num">Received</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.node} className={d.node === selected ? "is-selected" : ""} onClick={() => selectNode(d.node)}>
                <td><span className={`role role--${d.role}`}>{ROLE[d.role]}</span></td>
                <td className="mono ellipsis">{d.hostname ?? "—"}</td>
                <td className="mono">{d.ips.join(", ") || d.label}</td>
                <td className="mono">{d.mac ?? "—"}</td>
                <td className="ellipsis">{d.vendor ?? "—"}</td>
                <td className="num mono">{formatBytes(d.bytesSent)}</td>
                <td className="num mono">{formatBytes(d.bytesReceived)}</td>
                <td className="mono">{d.lastSeenUs ? formatTimestamp(d.lastSeenUs) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {devices.length === 0 && <p className="muted pad">No devices seen yet.</p>}
      </div>
    </section>
  );
}
