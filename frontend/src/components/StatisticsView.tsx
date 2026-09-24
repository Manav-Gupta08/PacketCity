import { formatBitRate, formatBytes, formatCount } from "../format";
import { useApp } from "../stores/appStore";
import { TRAFFIC_CLASSES } from "../types";
import { cssColor, VEHICLE_STYLES } from "../visualization/vehicleStyles";
import { TrafficChart } from "./BottomPanels";
import { Sparkline } from "./KpiBar";

function Figure({ label, value, warn }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className={`figure ${warn ? "figure--warn" : ""}`}>
      <span className="figure__label">{label}</span>
      <span className="figure__value mono">{value}</span>
    </div>
  );
}

export function StatisticsView() {
  const stats = useApp((s) => s.stats);
  const health = useApp((s) => s.health);
  const render = useApp((s) => s.render);
  const maxRate = stats ? Math.max(1, ...TRAFFIC_CLASSES.map((c) => stats.classRates[c] ?? 0)) : 1;

  return (
    <section className="page glass page--scroll" aria-label="Statistics">
      <header className="page__head">
        <h3>Statistics</h3>
        <span className="muted">Rolling 60-second window (one-second buckets) plus session totals.</span>
      </header>

      <div className="figures">
        <Figure label="Packets / s" value={stats ? formatCount(stats.packetsPerSec) : "—"} />
        <Figure label="Throughput" value={stats ? formatBitRate(stats.bytesPerSec) : "—"} />
        <Figure label="Download" value={stats ? formatBitRate(stats.downloadBytesPerSec) : "—"} />
        <Figure label="Upload" value={stats ? formatBitRate(stats.uploadBytesPerSec) : "—"} />
        <Figure label="Total packets" value={stats ? stats.totalPackets.toLocaleString() : "—"} />
        <Figure label="Total bytes" value={stats ? formatBytes(stats.totalBytes) : "—"} />
        <Figure label="Received / sent" value={stats ? `${formatBytes(stats.totalBytesIn)} / ${formatBytes(stats.totalBytesOut)}` : "—"} />
        <Figure label="Malformed" value={stats ? formatCount(stats.malformedPackets) : "—"} warn={!!stats?.malformedPackets} />
        <Figure label="Active flows" value={stats ? formatCount(stats.activeFlows) : "—"} />
        <Figure label="TCP established" value={stats ? formatCount(stats.activeConnections) : "—"} />
        <Figure label="Tracked flows" value={stats ? formatCount(stats.trackedFlows) : "—"} />
        <Figure label="Active devices" value={stats ? formatCount(stats.activeDevices) : "—"} />
      </div>

      <div className="stats-grid">
        <div className="panel glass">
          <h4 className="panel__title">Packets per second</h4>
          <Sparkline values={stats?.historyPackets ?? []} color="var(--blue)" height={120} />
        </div>
        <TrafficChart stats={stats} />
        <div className="panel glass">
          <h4 className="panel__title">Current rate by class</h4>
          <ul className="rate-bars">
            {TRAFFIC_CLASSES.map((c) => {
              const r = stats?.classRates[c] ?? 0;
              return (
                <li key={c}>
                  <span>{VEHICLE_STYLES[c].label}</span>
                  <span className="rate-bars__track">
                    <span style={{ width: `${(r / maxRate) * 100}%`, background: cssColor(VEHICLE_STYLES[c].color) }} />
                  </span>
                  <b className="mono">{formatCount(r)}/s</b>
                </li>
              );
            })}
          </ul>
        </div>
        <div className="panel glass">
          <h4 className="panel__title">Pipeline health</h4>
          <div className="figures figures--compact">
            <Figure label="Pipeline drops" value={health ? formatCount(health.framesDropped) : "—"} warn={!!health?.framesDropped} />
            <Figure label="Driver drops" value={health ? formatCount(health.driverDropped + health.interfaceDropped) : "—"} warn={!!health && health.driverDropped + health.interfaceDropped > 0} />
            <Figure label="Queue depth" value={health ? formatCount(health.queueDepth) : "—"} />
            <Figure label="Capture latency" value={health ? `${health.meanLatencyMs.toFixed(1)} ms` : "—"} />
            <Figure label="Render FPS" value={render.fps ? render.fps.toFixed(0) : "—"} warn={render.fps > 0 && render.fps < 45} />
            <Figure label="Vehicles" value={formatCount(render.vehicles)} />
            <Figure label="Merged into convoys" value={formatCount(render.mergedPackets)} />
          </div>
        </div>
      </div>
    </section>
  );
}
