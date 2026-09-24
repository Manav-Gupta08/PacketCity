import { formatBitRate, formatCount } from "../format";
import { setApp, useApp } from "../stores/appStore";
import { Icon, type IconName } from "./Icon";

export function Sparkline({ values, color, height = 26 }: { values: number[]; color: string; height?: number }) {
  const W = 120;
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? W / (values.length - 1) : W;
  const line = values.map((v, i) => `${(i * step).toFixed(1)},${(height - (v / max) * (height - 3) - 1).toFixed(1)}`).join(" ");
  return (
    <svg className="spark" viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none" aria-hidden>
      {values.length > 1 && <polygon points={`0,${height} ${line} ${W},${height}`} fill={color} opacity="0.14" />}
      <polyline points={line} fill="none" stroke={color} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

function Kpi({ icon, tone, label, value, sub, spark }: { icon: IconName; tone: string; label: string; value: string; sub?: string; spark?: number[] }) {
  return (
    <div className={`kpi glass kpi--${tone}`}>
      <span className="kpi__icon">
        <Icon name={icon} size={20} />
      </span>
      <div className="kpi__body">
        <span className="kpi__label">{label}</span>
        <span className="kpi__value mono">{value}</span>
        {spark ? <Sparkline values={spark} color={`var(--${tone})`} /> : <span className="kpi__sub">{sub}</span>}
      </div>
    </div>
  );
}

export function KpiBar() {
  const stats = useApp((s) => s.stats);
  const search = useApp((s) => s.search);
  const view = useApp((s) => s.view);

  return (
    <header className="kpis">
      <Kpi icon="packets" tone="blue" label="Total Packets" value={stats ? stats.totalPackets.toLocaleString() : "—"} sub={stats ? `${formatCount(stats.packetsPerSec)} pkt/s` : "no capture"} />
      <Kpi icon="down" tone="cyan" label="Download" value={stats ? formatBitRate(stats.downloadBytesPerSec) : "—"} spark={stats?.historyBytesIn} />
      <Kpi icon="up" tone="magenta" label="Upload" value={stats ? formatBitRate(stats.uploadBytesPerSec) : "—"} spark={stats?.historyBytesOut} />
      <Kpi icon="connections" tone="violet" label="Active Connections" value={stats ? formatCount(stats.activeConnections) : "—"} sub={stats ? `${formatCount(stats.activeFlows)} active flows` : ""} />
      <Kpi icon="devices" tone="mint" label="Devices" value={stats ? formatCount(stats.activeDevices + 1) : "—"} sub="seen on this segment" />
      <label className="search glass">
        <Icon name="search" size={16} />
        <input
          value={search}
          onChange={(e) => setApp({ search: e.target.value })}
          onKeyDown={(e) => {
            if (e.key === "Enter" && search.trim() && view !== "devices") setApp({ view: "connections" });
          }}
          placeholder="Search IP, domain, device…"
          spellCheck={false}
          aria-label="Search connections and devices"
        />
      </label>
    </header>
  );
}
