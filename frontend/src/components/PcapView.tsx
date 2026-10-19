import { formatBytes, formatDuration, formatTimestamp } from "../format";
import { openCaptureFile, stopSession } from "../services/session";
import { setApp, useApp } from "../stores/appStore";
import { Icon } from "./Icon";

export function PcapView() {
  const session = useApp((s) => s.session);
  const phase = useApp((s) => s.phase);
  const replay = session?.source === "replay" && phase === "running" ? session.replay : null;

  return (
    <section className="page glass" aria-label="PCAP viewer">
      <header className="page__head">
        <h3>PCAP Viewer</h3>
        <span className="muted">Replay a saved capture through the same visualization, flows and inspector.</span>
      </header>

      <div className="pcap-open">
        <button className="btn btn--primary btn--lg" onClick={() => void openCaptureFile()}>
          <Icon name="pcap" /> Open capture file…
        </button>
        <p className="muted">
          Supports <b>.pcap</b> and <b>.pcapng</b> (Ethernet, loopback, raw IP, Linux cooked). Files are read locally and never
          uploaded. Opening a file stops any live capture.
        </p>
      </div>

      {replay && session && (
        <div className="pcap-info">
          <h4>{replay.fileName}</h4>
          <dl className="kv kv--wide">
            <div className="kv__row"><dt>Packets</dt><dd className="mono">{replay.packets.toLocaleString()}</dd></div>
            <div className="kv__row"><dt>Size on wire</dt><dd className="mono">{formatBytes(replay.bytes)}</dd></div>
            <div className="kv__row"><dt>Recorded</dt><dd className="mono">{new Date(replay.firstUs / 1000).toLocaleDateString()} {formatTimestamp(replay.firstUs)}</dd></div>
            <div className="kv__row"><dt>Duration</dt><dd className="mono">{formatDuration(Math.round((replay.lastUs - replay.firstUs) / 1000))}</dd></div>
            <div className="kv__row"><dt>Link type</dt><dd className="mono">{replay.link}</dd></div>
            <div className="kv__row">
              <dt>Recording host</dt>
              <dd>
                <span className="mono">{replay.inferredHost ?? "unknown"}{replay.inferredPrefix ? `/${replay.inferredPrefix}` : ""}</span>{" "}
                <span className="muted">({replay.prefixSource === "arp" ? "subnet from ARP" : "subnet assumed"})</span>
              </dd>
            </div>
            {replay.skippedFrames > 0 && (
              <div className="kv__row"><dt>Skipped</dt><dd>{replay.skippedFrames.toLocaleString()} frames from interfaces with a different link type</dd></div>
            )}
          </dl>
          <p className="muted">
            A capture file does not record which machine captured it, so "this host" is inferred as the private address present
            in the most packets. Incoming/outgoing are relative to that host.
          </p>
          <div className="pcap-actions">
            <button className="btn btn--glass" onClick={() => setApp({ view: "global" })}>Show in Live Traffic</button>
            <button className="btn btn--glass" onClick={() => setApp({ view: "myTraffic" })}>Show in My Traffic</button>
            <button className="btn btn--danger" onClick={() => void stopSession()}>Close replay</button>
          </div>
        </div>
      )}
    </section>
  );
}
