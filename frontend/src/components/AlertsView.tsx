import { useEffect } from "react";

import { formatTimestamp } from "../format";
import { selectFlow, selectNode } from "../services/session";
import { setApp, useApp } from "../stores/appStore";
import type { Alert } from "../types";

const KIND_LABEL: Record<Alert["kind"], string> = {
  duplicateIp: "Address conflict",
  newDevice: "New device",
  portScan: "Port scan",
  hostSweep: "Host sweep",
  retransmissions: "Retransmissions",
  malformedTraffic: "Malformed traffic",
};

function focus(a: Alert) {
  if (a.flowId !== null) selectFlow(a.flowId);
  else if (a.node) selectNode(a.node);
  setApp({ view: "global" });
}

export function AlertsView() {
  const alerts = useApp((s) => s.alerts);
  const phase = useApp((s) => s.phase);

  useEffect(() => {
    const newest = alerts.at(-1)?.id ?? 0;
    if (newest > useApp.getState().alertsSeenId) setApp({ alertsSeenId: newest });
  }, [alerts]);

  return (
    <section className="page glass" aria-label="Alerts">
      <header className="page__head">
        <h3>Alerts</h3>
        <span className="muted">Explainable detections from the traffic this interface sees. Each alert states its evidence.</span>
      </header>
      {alerts.length === 0 ? (
        <p className="muted pad">{phase === "idle" ? "Start a capture to begin detection." : "No alerts. Thresholds are deliberately conservative."}</p>
      ) : (
        <ul className="alerts">
          {[...alerts].reverse().map((a) => (
            <li key={a.id} className={`alert alert--${a.severity}`}>
              <div className="alert__head">
                <span className={`alert__sev alert__sev--${a.severity}`}>{a.severity === "warning" ? "WARNING" : "INFO"}</span>
                <span className="alert__kind">{KIND_LABEL[a.kind]}</span>
                <span className="alert__time mono">{formatTimestamp(a.timestampUs)}</span>
              </div>
              <div className="alert__title">{a.title}</div>
              <p className="alert__detail">{a.detail}</p>
              {(a.node || a.flowId !== null) && (
                <button className="btn btn--glass" onClick={() => focus(a)}>
                  Show on map →
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <footer className="page__foot muted">
        Rules: address conflicts (one IP, two MACs) · new devices after a 60 s warm-up · ≥20 ports probed on one host or ≥20
        local hosts probed on one port within 10 s · TCP flows with ≥10% retransmissions (≥50 packets) · bursts of malformed
        packets. Repeats are suppressed for 5 minutes.
      </footer>
    </section>
  );
}
