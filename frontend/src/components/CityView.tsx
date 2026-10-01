import { useEffect, useMemo, useRef, useState } from "react";

import { formatBitRate, formatBytes, formatCount } from "../format";
import { selectNode, selectVehicle, togglePause } from "../services/session";
import { trafficBus } from "../services/trafficBus";
import { getApp, setApp, useApp } from "../stores/appStore";
import type { DeviceSnapshot, FlowSnapshot, StatsSnapshot, TrafficClass } from "../types";
import { TRAFFIC_CLASSES } from "../types";
import { compileFilter, parseFilter } from "../visualization/filter";
import { internetHostnames, rankDestinations, stickyDestinations, type Destination } from "../visualization/destinations";
import { CityRenderer, type HoverInfo } from "../visualization/iso/CityRenderer";
import { type Scene, type SignSpec } from "../visualization/iso/scene";
import { buildGlobalScene } from "../visualization/scenes/globalScene";
import { buildPersonalScene } from "../visualization/scenes/personalScene";
import { cssColor, THREAT_COLOR, THREAT_LABELS, threatColor, VEHICLE_STYLES } from "../visualization/vehicleStyles";
import { Icon } from "./Icon";
import { ReplayBar } from "./ReplayBar";

/** Minimum interval between Global scene rebuilds driven by device updates. */
const SCENE_REBUILD_MS = 2000;
const HEIGHT_BUCKET_BYTES = 10;

type Mode = "global" | "personal";

function deviceSignature(devices: DeviceSnapshot[]): string {
  // Rebuild only when the set, labels or traffic order-of-magnitude of devices changes.
  return devices
    .map((d) => `${d.node}|${d.label}|${Math.floor(Math.log(1 + d.bytesSent + d.bytesReceived) / Math.log(HEIGHT_BUCKET_BYTES))}`)
    .join(";");
}

const destinationSignature = (destinations: Destination[]): string => destinations.map((d) => d.name).join(";");

function topRemoteHosts(flows: FlowSnapshot[]): string {
  const hosts = new Map<string, number>();
  for (const f of internetHostnames(flows)) {
    hosts.set(f.hostname!, (hosts.get(f.hostname!) ?? 0) + f.bytes);
  }
  return [...hosts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2)
    .map(([h]) => h)
    .join(" · ");
}

function signSub(sign: SignSpec, stats: StatsSnapshot | null, flows: FlowSnapshot[], devices: DeviceSnapshot[]): string | undefined {
  switch (sign.id) {
    case "in":
      return stats ? formatBitRate(stats.downloadBytesPerSec) : undefined;
    case "out":
      return stats ? formatBitRate(stats.uploadBytesPerSec) : undefined;
    case "internet":
      return topRemoteHosts(flows) || sign.sub;
    default: {
      if (sign.id.startsWith("dest:")) {
        const name = sign.id.slice(5);
        const bytes = flows.reduce((sum, f) => (f.hostname === name ? sum + f.bytes : sum), 0);
        return bytes ? formatBytes(bytes) : undefined;
      }
      const d = sign.node ? devices.find((x) => x.node === sign.node) : undefined;
      if (d && d.role === "lan") return formatBytes(d.bytesSent + d.bytesReceived);
      return sign.sub;
    }
  }
}

export function CityView({ mode, visible }: { mode: Mode; visible: boolean }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const rendererRef = useRef<CityRenderer | null>(null);
  const lastRebuild = useRef({ at: 0, signature: "", mode: "" as string, session: -1 });
  const shownDestinations = useRef<string[]>([]);
  const [scene, setScene] = useState<Scene | null>(null);
  const [hover, setHover] = useState<HoverInfo | null>(null);
  const [renderError, setRenderError] = useState<string | null>(null);

  const paused = useApp((s) => s.paused);
  const vizFilter = useApp((s) => s.vizFilter);
  const phase = useApp((s) => s.phase);
  const session = useApp((s) => s.session);
  const stats = useApp((s) => s.stats);
  const flows = useApp((s) => s.flows);
  const devices = useApp((s) => s.devices);
  const focusFlowId = useApp((s) => s.focusFlowId);
  const selectedNode = useApp((s) => s.selection.node);
  const parsedFilter = useMemo(() => parseFilter(vizFilter), [vizFilter]);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const renderer = new CityRenderer({
      onHover: setHover,
      onSelectVehicle: (ev) => selectVehicle(ev.packetId, ev.flowId),
      onSelectNode: selectNode,
      onMetrics: (render) => setApp({ render }),
    });
    rendererRef.current = renderer;
    if (import.meta.env.DEV) (window as unknown as Record<string, unknown>)[`__city_${mode}`] = renderer;
    renderer.init(host, overlayRef.current).catch((e: unknown) => setRenderError(e instanceof Error ? e.message : String(e)));
    return () => {
      renderer.destroy();
      rendererRef.current = null;
    };
  }, []);

  // Build or refresh the scene: on mode/session change immediately, on device changes throttled.
  useEffect(() => {
    const r = rendererRef.current;
    const sessionId = session?.id ?? -1;
    const last = lastRebuild.current;
    const modeChanged = last.mode !== mode || last.session !== sessionId;
    if (modeChanged) shownDestinations.current = [];
    const destinations = stickyDestinations(shownDestinations.current, rankDestinations(flows));
    const base = mode === "global" ? deviceSignature(devices) : String(session?.localAddresses[0] ?? "");
    const signature = `${base}#${destinationSignature(destinations)}`;
    const now = performance.now();
    if (!modeChanged && (signature === last.signature || now - last.at < SCENE_REBUILD_MS)) return;
    const localLabel = session?.localAddresses.find((a) => !a.includes(":")) ?? session?.localAddresses[0] ?? "";
    const next = mode === "global" ? buildGlobalScene(devices, destinations) : buildPersonalScene(localLabel, destinations);
    shownDestinations.current = destinations.map((d) => d.name);
    lastRebuild.current = { at: now, signature, mode, session: sessionId };
    r?.setScene(next, modeChanged);
    setScene(next);
  }, [mode, devices, flows, session]);

  useEffect(() => rendererRef.current?.setPaused(paused), [paused]);
  useEffect(() => {
    rendererRef.current?.setActive(visible);
    if (visible) trafficBus.clear();
  }, [visible]);
  useEffect(() => rendererRef.current?.setFilter(compileFilter(parsedFilter)), [parsedFilter]);
  useEffect(() => rendererRef.current?.setFocusFlow(focusFlowId), [focusFlowId]);
  useEffect(() => rendererRef.current?.setSelectedNode(selectedNode), [selectedNode]);
  useEffect(
    () =>
      useApp.subscribe((s, prev) => {
        if (s.selection !== prev.selection) rendererRef.current?.setSelectedPacket(s.selection.packetId);
        if (s.stats && s.stats !== prev.stats) rendererRef.current?.setTraffic(s.stats.packetsPerSec);
        if (s.replay && prev.replay && s.replay.generation !== prev.replay.generation) rendererRef.current?.reset();
      }),
    [],
  );

  const hiddenClasses = useMemo(
    () => new Set(parsedFilter.terms.filter((t) => t.negate && t.key === "class").map((t) => t.value)),
    [parsedFilter],
  );
  const toggleClass = (c: TrafficClass) => {
    const term = `!class:${c}`;
    const current = getApp().vizFilter.split(/\s+/).filter(Boolean);
    const next = current.includes(term) ? current.filter((t) => t !== term) : [...current, term];
    setApp({ vizFilter: next.join(" ") });
  };
  const threatOnly = parsedFilter.terms.some((t) => t.key === "threat" && !t.negate);
  const toggleThreatOnly = () => {
    const current = getApp().vizFilter.split(/\s+/).filter((t) => t && t !== "threat" && t !== "malicious");
    setApp({ vizFilter: (threatOnly ? current : [...current, "threat"]).join(" ") });
  };

  return (
    <section className={`city ${session?.source === "replay" ? "city--replay" : ""}`} aria-label={mode === "global" ? "Global network city" : "My traffic highway"}>
      <div ref={hostRef} className="city__canvas" />
      <div className="city__signs-clip">
        <div ref={overlayRef} className="city__signs">
          {scene?.model.signs.map((s) => {
            const sub = signSub(s, stats, flows, devices);
            return (
              <div
                key={s.id}
                data-sign={s.id}
                className={`sign sign--${s.tone} sign--${s.size} ${s.node ? "is-link" : ""} ${s.node && s.node === selectedNode ? "is-selected" : ""}`}
                style={{ display: "none" }}
                onClick={s.node ? () => selectNode(s.node!) : undefined}
              >
                <span className="sign__text">{s.text}</span>
                {sub && <span className="sign__sub">{sub}</span>}
              </div>
            );
          })}
        </div>
      </div>

      <div className="legend glass">
        <div className="panel-title">TRAFFIC TYPES</div>
        {TRAFFIC_CLASSES.map((c) => {
          const s = VEHICLE_STYLES[c];
          const off = hiddenClasses.has(c);
          return (
            <button key={c} className={`legend__item ${off ? "is-off" : ""}`} onClick={() => toggleClass(c)} title={off ? "Show" : "Hide"}>
              <i className={`legend__swatch legend__swatch--${s.shape}`} style={{ background: cssColor(s.color) }} />
              {s.label}
            </button>
          );
        })}
        <div className="legend__sep" />
        <button
          className={`legend__item legend__item--threat ${threatOnly ? "is-on" : ""}`}
          onClick={toggleThreatOnly}
          title={threatOnly ? "Show all traffic" : "Show only suspicious traffic"}
        >
          <i className="legend__swatch legend__swatch--threat" style={{ background: cssColor(THREAT_COLOR) }} />
          Suspicious
          {stats && stats.threatPackets > 0 && <span className="legend__count mono">{formatCount(stats.threatPackets)}</span>}
        </button>
      </div>

      <div className="city__toolbar">
        <button className={`btn btn--glass ${paused ? "is-active" : ""}`} onClick={togglePause} disabled={phase !== "running"} title={paused ? "Resume" : "Pause"}>
          <Icon name={paused ? "play" : "pause"} size={15} />
          {paused ? "Resume" : "Pause"}
        </button>
        <label className={`viz-filter glass ${parsedFilter.errors.length ? "has-error" : ""}`} title={parsedFilter.errors[0] ?? "Display only · capture is unaffected"}>
          <span className="viz-filter__label">VIEW</span>
          <input
            value={vizFilter}
            onChange={(e) => setApp({ vizFilter: e.target.value })}
            placeholder="tcp  dns  port:443  ip:10.0.0.*  host:example  !arp"
            spellCheck={false}
            aria-label="View filter"
          />
        </label>
        {focusFlowId !== null && (
          <button className="chip chip--focus" onClick={() => setApp({ focusFlowId: null })}>
            Following flow #{focusFlowId} ✕
          </button>
        )}
        <div className="city__zoom glass">
          <button onClick={() => rendererRef.current?.zoomBy(1.25)} aria-label="Zoom in"><Icon name="plus" size={15} /></button>
          <button onClick={() => rendererRef.current?.zoomBy(0.8)} aria-label="Zoom out"><Icon name="minus" size={15} /></button>
          <button onClick={() => rendererRef.current?.fit()} aria-label="Fit view"><Icon name="fit" size={15} /></button>
        </div>
      </div>

      <ScopeChip />
      {session?.source === "replay" && phase === "running" && <ReplayBar />}
      <PipelineStrip />

      {hover && <VehicleTooltip info={hover} />}
      {phase === "idle" && !renderError && (
        <div className="stage-message">
          <div>
            <h2>No capture running</h2>
            <p>Choose an interface and press Start capture, or launch the clearly labelled demo.</p>
          </div>
        </div>
      )}
      {paused && <div className="paused-badge">PAUSED · capture continues</div>}
      {renderError && (
        <div className="stage-message stage-message--error">
          <div>
            <h2>Visualization unavailable</h2>
            <p>The graphics renderer could not start ({renderError}). Capture and statistics still work.</p>
          </div>
        </div>
      )}
    </section>
  );
}

function ScopeChip() {
  const session = useApp((s) => s.session);
  const phase = useApp((s) => s.phase);
  if (!session || phase === "idle") return null;
  const demo = session.source === "demo";
  const title = demo ? "DEMO MODE" : session.source === "replay" ? "REPLAY" : "CAPTURE SCOPE";
  return (
    <details className={`scope glass ${demo ? "scope--demo" : ""}`}>
      <summary>
        <b>{title}</b> {demo ? "synthetic traffic" : session.scope.mode}
      </summary>
      <dl>
        <dt>Interface</dt>
        <dd>{demo ? "None (synthetic)" : session.source === "replay" ? "None (capture file)" : (session.interface?.displayName ?? "—")}</dd>
        <dt>Visibility</dt>
        <dd>{session.scope.visibility}</dd>
        {session.captureFilter && (
          <>
            <dt>Filter</dt>
            <dd className="mono">{session.captureFilter}</dd>
          </>
        )}
      </dl>
    </details>
  );
}

function PipelineStrip() {
  const render = useApp((s) => s.render);
  const health = useApp((s) => s.health);
  const drops = health ? health.framesDropped + health.driverDropped + health.interfaceDropped : 0;
  const items: [string, string, boolean?][] = [
    ["FPS", render.fps ? render.fps.toFixed(0) : "—", render.fps > 0 && render.fps < 45],
    ["vehicles", formatCount(render.vehicles)],
    ["convoy-merged", formatCount(render.mergedPackets)],
    ["queued", formatCount(render.waiting)],
    ["drops", health ? formatCount(drops) : "—", drops > 0],
    ["latency", health ? `${health.meanLatencyMs.toFixed(1)} ms` : "—"],
    ["off-map", formatCount(render.offMapPackets)],
  ];
  return (
    <div className="pipeline mono" aria-label="Pipeline health">
      {items.map(([k, v, warn]) => (
        <span key={k} className={warn ? "is-warn" : ""}>
          {k} <b>{v}</b>
        </span>
      ))}
    </div>
  );
}

function VehicleTooltip({ info }: { info: HoverInfo }) {
  const e = info.event;
  const style = VEHICLE_STYLES[e.class];
  const ep = (addr: string, port: number | null) => (port === null ? addr : addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`);
  return (
    <div className={`tooltip glass ${e.threat ? "tooltip--threat" : ""}`} style={{ left: info.x + 14, top: info.y + 14 }}>
      <div className="tooltip__head" style={{ color: cssColor(e.threat ? threatColor(e.threat) : style.color) }}>
        {style.label} · {e.direction.toUpperCase()}
      </div>
      {e.threat && <div className="tooltip__threat">⚠ {THREAT_LABELS[e.threat].title}</div>}
      <div className="mono">{ep(e.src, e.srcPort)}</div>
      <div className="mono">→ {ep(e.dst, e.dstPort)}</div>
      {e.host && <div className="tooltip__host">{e.host}</div>}
      <div className="tooltip__meta">
        {e.packets > 1 ? `Convoy of ${e.packets} packets · ${formatBytes(e.bytes)}` : `${e.length} bytes`} · click to inspect
      </div>
    </div>
  );
}
