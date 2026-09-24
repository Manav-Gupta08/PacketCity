import { refreshInterfaces, startDemo, startLive, stopSession } from "../services/session";
import { setApp, useApp, type View } from "../stores/appStore";
import type { InterfaceInfo } from "../types";
import { Icon, type IconName } from "./Icon";

interface NavItem {
  label: string;
  icon: IconName;
  view: View;
}

const NAV: NavItem[] = [
  { label: "Live Traffic", icon: "live", view: "global" },
  { label: "My Traffic", icon: "car", view: "myTraffic" },
  { label: "Connections", icon: "connections", view: "connections" },
  { label: "Devices", icon: "devices", view: "devices" },
  { label: "Protocols", icon: "protocols", view: "protocols" },
  { label: "Alerts", icon: "alerts", view: "alerts" },
  { label: "PCAP Viewer", icon: "pcap", view: "pcap" },
  { label: "Statistics", icon: "stats", view: "statistics" },
  { label: "Settings", icon: "settings", view: "settings" },
];

const KIND_LABEL: Record<InterfaceInfo["kind"], string> = {
  ethernet: "Ethernet",
  wireless: "Wi-Fi",
  loopback: "Loopback",
  virtual: "Virtual",
  unknown: "Adapter",
};

function interfaceLabel(i: InterfaceInfo): string {
  const v4 = i.addresses.find((a) => !a.address.includes(":"))?.address;
  const state = i.connected === false ? " · disconnected" : "";
  return `${KIND_LABEL[i.kind]} — ${i.displayName}${v4 ? ` (${v4})` : ""}${state}`;
}

function CapturePanel() {
  const env = useApp((s) => s.environment);
  const interfaces = useApp((s) => s.interfaces);
  const selectedId = useApp((s) => s.selectedInterfaceId);
  const promiscuous = useApp((s) => s.promiscuous);
  const captureFilter = useApp((s) => s.captureFilter);
  const phase = useApp((s) => s.phase);
  const session = useApp((s) => s.session);

  const busy = phase === "starting";
  const running = phase === "running";
  const locked = running || busy;
  const isDemo = session?.source === "demo" && running;
  const isReplay = session?.source === "replay" && running;

  return (
    <section className="capture" aria-label="Capture">
      <div className="capture__head">
        <span className="panel-title">CAPTURE</span>
        <span className={`status-pill status-pill--${running ? (isDemo ? "demo" : isReplay ? "replay" : "live") : phase}`} role="status">
          <span className="status-pill__dot" />
          {running ? (isDemo ? "DEMO" : isReplay ? "REPLAY" : "LIVE") : busy ? "STARTING" : phase === "ended" ? "STOPPED" : "IDLE"}
        </span>
      </div>
      <div className="capture__row">
        <select
          className="field field--select"
          value={selectedId ?? ""}
          onChange={(e) => setApp({ selectedInterfaceId: e.target.value })}
          disabled={locked || interfaces.length === 0}
          aria-label="Capture interface"
          title={interfaces.find((i) => i.id === selectedId)?.displayName}
        >
          {interfaces.length === 0 && <option value="">No interfaces</option>}
          {interfaces.map((i) => (
            <option key={i.id} value={i.id}>
              {interfaceLabel(i)}
            </option>
          ))}
        </select>
        <button className="btn btn--icon" onClick={refreshInterfaces} disabled={locked || !env?.driverAvailable} title="Refresh interfaces" aria-label="Refresh interfaces">
          <Icon name="refresh" size={15} />
        </button>
      </div>
      <input
        className="field field--filter mono"
        value={captureFilter}
        onChange={(e) => setApp({ captureFilter: e.target.value })}
        placeholder="BPF filter, e.g. not port 22"
        disabled={locked}
        spellCheck={false}
        aria-label="Capture filter (BPF)"
        title="Applied in the capture driver. Changing it requires restarting capture."
      />
      <label className="toggle" title="Ask the adapter to deliver frames addressed to other hosts. Often unsupported on Wi-Fi.">
        <input type="checkbox" checked={promiscuous} onChange={(e) => setApp({ promiscuous: e.target.checked })} disabled={locked} />
        Promiscuous mode
      </label>
      <div className="capture__row">
        {running ? (
          <button className="btn btn--danger btn--grow" onClick={stopSession}>
            ■ Stop
          </button>
        ) : (
          <button className="btn btn--primary btn--grow" onClick={startLive} disabled={!env?.driverAvailable || !selectedId || busy}>
            ● Start capture
          </button>
        )}
        <button className="btn btn--demo" onClick={startDemo} disabled={locked} title="Synthetic traffic — not real data">
          Demo
        </button>
      </div>
    </section>
  );
}

export function Sidebar() {
  const view = useApp((s) => s.view);
  const unread = useApp((s) => s.alerts.filter((a) => a.id > s.alertsSeenId).length);
  return (
    <aside className="sidebar glass">
      <div className="brand">
        <span className="brand__mark" aria-hidden />
        <div>
          <div className="brand__name">
            Packet<b>City</b>
          </div>
          <div className="brand__tag">VISUAL NETWORK ANALYZER</div>
        </div>
      </div>
      <nav className="nav" aria-label="Main navigation">
        {NAV.map((item) => (
          <button
            key={item.label}
            className={`nav__item ${view === item.view ? "is-active" : ""}`}
            onClick={() => setApp({ view: item.view })}
            aria-current={view === item.view ? "page" : undefined}
          >
            <Icon name={item.icon} />
            {item.label}
            {item.view === "alerts" && unread > 0 && <span className="nav__badge">{unread > 99 ? "99+" : unread}</span>}
          </button>
        ))}
      </nav>
      <CapturePanel />
    </aside>
  );
}
