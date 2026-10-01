import { useDeferredValue, useMemo } from "react";

import { formatBytes, formatDuration } from "../format";
import { selectFlow } from "../services/session";
import { useApp } from "../stores/appStore";
import type { FlowSnapshot } from "../types";
import { cssColor, THREAT_LABELS, threatColor, VEHICLE_STYLES } from "../visualization/vehicleStyles";

function matches(f: FlowSnapshot, q: string): boolean {
  if (!q) return true;
  const hay = `${f.initiator} ${f.responder} ${f.hostname ?? ""} ${f.protocol} ${f.class} ${f.app} ${f.id} ${f.threat ? "threat malicious suspicious" : ""}`.toLowerCase();
  return q.split(/\s+/).every((t) => hay.includes(t));
}

export function ConnectionsView() {
  const flows = useApp((s) => s.flows);
  const selectedFlow = useApp((s) => s.selection.flowId);
  const search = useApp((s) => s.search);
  const deferred = useDeferredValue(search.trim().toLowerCase());
  const rows = useMemo(() => flows.filter((f) => matches(f, deferred)), [flows, deferred]);

  return (
    <section className="table-view glass" aria-label="Connections">
      <div className="table-view__head">
        <h3>Connections</h3>
        <span className="muted">
          {rows.length} of {flows.length} recently active flows{deferred ? ` matching “${deferred}”` : ""}
        </span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Flow</th>
              <th>Class</th>
              <th>Initiator</th>
              <th>Responder</th>
              <th>Host</th>
              <th>Dir</th>
              <th className="num">Packets</th>
              <th className="num">↑ Up</th>
              <th className="num">↓ Down</th>
              <th className="num">Duration</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr
                key={f.id}
                className={`${f.id === selectedFlow ? "is-selected" : ""} ${f.threat ? "is-threat" : ""}`}
                onClick={() => selectFlow(f.id)}
                title={f.threat ? `Suspicious: ${THREAT_LABELS[f.threat].title}` : undefined}
              >
                <td className="mono">{f.threat ? "⚠ " : ""}#{f.id}</td>
                <td>
                  <span className="dot" style={{ background: cssColor(f.threat ? threatColor(f.threat) : VEHICLE_STYLES[f.class].color) }} />
                  {VEHICLE_STYLES[f.class].label}
                </td>
                <td className="mono">{f.initiator}</td>
                <td className="mono">{f.responder}</td>
                <td className="mono ellipsis">{f.hostname ?? ""}</td>
                <td>{f.direction === "outgoing" ? "→" : f.direction === "incoming" ? "←" : f.direction}</td>
                <td className="num mono">{f.packets.toLocaleString()}</td>
                <td className="num mono">{formatBytes(f.bytesOut)}</td>
                <td className="num mono">{formatBytes(f.bytesIn)}</td>
                <td className="num mono">{formatDuration(f.durationMs)}</td>
                <td>{f.tcp?.state ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {flows.length === 0 && <p className="muted pad">No active flows yet.</p>}
      </div>
    </section>
  );
}
