import { useState } from "react";

import { api, toCommandError } from "../services/ipc";
import { exportKeptPackets } from "../services/session";
import { DEMO_RATE_KEY, setApp, useApp } from "../stores/appStore";

const DEMO_PRESETS = [120, 1_000, 5_000, 10_000];
const DEMO_MAX = 50_000;

async function setPayloadCapture(enabled: boolean) {
  try {
    await api.setPayloadCapture(enabled);
    setApp({ payloadCapture: enabled });
  } catch (e) {
    setApp({ error: toCommandError(e) });
  }
}

export function SettingsView() {
  const demoRate = useApp((s) => s.demoRate);
  const env = useApp((s) => s.environment);
  const payloadCapture = useApp((s) => s.payloadCapture);
  const hasSession = useApp((s) => s.session !== null && s.phase !== "idle");
  const [custom, setCustom] = useState("");
  const [exported, setExported] = useState<string | null>(null);

  const setRate = (rate: number) => {
    if (!Number.isFinite(rate) || rate <= 0) return;
    const r = Math.min(DEMO_MAX, Math.round(rate));
    localStorage.setItem(DEMO_RATE_KEY, String(r));
    setApp({ demoRate: r });
  };

  return (
    <section className="page glass page--scroll" aria-label="Settings">
      <header className="page__head">
        <h3>Settings</h3>
      </header>

      <div className="settings">
        <section className="setting">
          <h4>Demo traffic rate</h4>
          <p className="muted">
            Packets per second produced by the clearly labelled demo generator. Higher rates are useful for testing how the
            visualization degrades under load. Applies the next time Demo is started.
          </p>
          <div className="setting__row">
            {DEMO_PRESETS.map((r) => (
              <button key={r} className={`chip ${demoRate === r ? "is-on" : ""}`} onClick={() => setRate(r)}>
                {r.toLocaleString()} pkt/s
              </button>
            ))}
            <input
              className="field field--narrow mono"
              value={custom}
              onChange={(e) => setCustom(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  setRate(Number(custom));
                  setCustom("");
                }
              }}
              placeholder={DEMO_PRESETS.includes(demoRate) ? "custom" : String(demoRate)}
              aria-label={`Custom demo rate, up to ${DEMO_MAX}`}
            />
          </div>
        </section>

        <section className="setting">
          <h4>Packet bytes (hex view)</h4>
          <p className="muted">
            When on, the raw bytes of the most recent 5,000 packets are kept in memory so the inspector can show a hex dump.
            This includes <b>payload contents</b> (anything unencrypted: HTTP bodies, DNS, cookies on plain HTTP). Bytes are
            only written to disk if you export them below, are discarded as soon as you turn this off, and the setting resets
            to off at every launch.
          </p>
          <div className="setting__row">
            <button className={`chip ${payloadCapture ? "" : "is-on"}`} onClick={() => void setPayloadCapture(false)} aria-pressed={!payloadCapture}>
              Off — headers only
            </button>
            <button className={`chip ${payloadCapture ? "is-on is-warn" : ""}`} onClick={() => void setPayloadCapture(true)} aria-pressed={payloadCapture}>
              On — keep packet bytes
            </button>
          </div>
        </section>

        <section className="setting">
          <h4>Export to PCAP</h4>
          <p className="muted">
            Saves the packets currently kept in memory (up to the last 5,000, oldest first) as a standard <span className="mono">.pcap</span>{" "}
            file that Wireshark, tcpdump or PacketCity's own PCAP Viewer can open. Requires packet bytes to be on.
          </p>
          <div className="setting__row">
            <button
              className="btn btn--glass"
              disabled={!payloadCapture || !hasSession}
              onClick={() => void exportKeptPackets().then((msg) => msg && setExported(msg))}
              title={!payloadCapture ? "Turn on packet bytes first" : !hasSession ? "Start a capture first" : "Choose where to save"}
            >
              Export kept packets…
            </button>
            {exported && <span className="muted mono wrap">{exported}</span>}
          </div>
        </section>

        <section className="setting">
          <h4>Privacy</h4>
          <ul className="setting__list">
            <li>Captured traffic never leaves this computer: no cloud services, no uploads, no telemetry.</li>
            <li>
              {payloadCapture
                ? "Packet bytes are currently being kept in memory for the hex view (see above)."
                : "Payload bytes are not stored. Only header metadata is kept, plus DNS names, TLS server names and HTTP method/host/path (query strings dropped)."}
            </li>
            <li>The inspector keeps the most recent 50,000 packets in memory; nothing is written to disk unless you export it.</li>
            <li>Capture files opened in the PCAP Viewer are read locally and are not modified.</li>
          </ul>
        </section>

        <section className="setting">
          <h4>Capture driver</h4>
          <dl className="kv kv--wide">
            <div className="kv__row"><dt>Platform</dt><dd>{env?.platform ?? "—"}</dd></div>
            <div className="kv__row"><dt>Library</dt><dd className="mono">{env?.driverVersion ?? env?.driverMessage ?? "—"}</dd></div>
            <div className="kv__row"><dt>Permissions</dt><dd className="muted">{env?.permissionHint ?? "—"}</dd></div>
          </dl>
        </section>
      </div>
    </section>
  );
}
