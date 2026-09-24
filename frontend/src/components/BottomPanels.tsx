import { useMemo } from "react";

import { formatBitRate, formatBytes, formatCount } from "../format";
import { selectFlow } from "../services/session";
import { useApp } from "../stores/appStore";
import { TRAFFIC_CLASSES, type StatsSnapshot } from "../types";
import { cssColor, VEHICLE_STYLES } from "../visualization/vehicleStyles";

const DONUT_RADIUS = 52;
const DONUT_STROKE = 18;
const TOP_CONNECTIONS = 6;

function ProtocolDonut({ stats }: { stats: StatsSnapshot | null }) {
  const total = stats ? TRAFFIC_CLASSES.reduce((s, c) => s + (stats.classTotals[c] ?? 0), 0) : 0;
  const circumference = 2 * Math.PI * DONUT_RADIUS;
  let offset = 0;
  const slices = TRAFFIC_CLASSES.map((c) => {
    const n = stats?.classTotals[c] ?? 0;
    const frac = total ? n / total : 0;
    const slice = { c, frac, dash: frac * circumference, offset };
    offset += slice.dash;
    return slice;
  });
  const rows = slices.filter((s) => s.frac > 0).sort((a, b) => b.frac - a.frac).slice(0, 6);

  return (
    <section className="panel glass">
      <h4 className="panel__title">Protocol Distribution</h4>
      <div className="donut">
        <svg viewBox="0 0 140 140" className="donut__svg" aria-hidden>
          <circle cx="70" cy="70" r={DONUT_RADIUS} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={DONUT_STROKE} />
          {slices.map((s) =>
            s.frac > 0 ? (
              <circle
                key={s.c}
                cx="70"
                cy="70"
                r={DONUT_RADIUS}
                fill="none"
                stroke={cssColor(VEHICLE_STYLES[s.c].color)}
                strokeWidth={DONUT_STROKE}
                strokeDasharray={`${Math.max(0, s.dash - 1.5)} ${circumference}`}
                strokeDashoffset={-s.offset}
                transform="rotate(-90 70 70)"
              />
            ) : null,
          )}
          <text x="70" y="68" textAnchor="middle" className="donut__value">{formatCount(total)}</text>
          <text x="70" y="86" textAnchor="middle" className="donut__label">Packets</text>
        </svg>
        <ul className="donut__legend">
          {rows.length === 0 && <li className="muted">No traffic yet</li>}
          {rows.map((s) => (
            <li key={s.c}>
              <i style={{ background: cssColor(VEHICLE_STYLES[s.c].color) }} />
              {VEHICLE_STYLES[s.c].label}
              <b className="mono">{Math.round(s.frac * 100)}%</b>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

export function TrafficChart({ stats }: { stats: StatsSnapshot | null }) {
  const W = 480;
  const H = 150;
  const PAD_L = 58;
  const PAD_B = 20;
  const down = stats?.historyBytesIn ?? [];
  const up = stats?.historyBytesOut ?? [];
  const max = Math.max(1, ...down, ...up);
  const n = Math.max(down.length, 2);
  const x = (i: number) => PAD_L + (i / (n - 1)) * (W - PAD_L - 4);
  const y = (v: number) => H - PAD_B - (v / max) * (H - PAD_B - 8);
  const line = (vals: number[]) => vals.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = (vals: number[]) => (vals.length ? `${x(0)},${y(0)} ${line(vals)} ${x(vals.length - 1)},${y(0)}` : "");
  const ticks = [0, 0.5, 1];

  return (
    <section className="panel glass">
      <div className="panel__head">
        <h4 className="panel__title">Traffic Over Time</h4>
        <span className="chart-legend"><i className="c-down" />Download <i className="c-up" />Upload</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart" preserveAspectRatio="none" aria-label="Download and upload over the last 60 seconds">
        <defs>
          <linearGradient id="g-down" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="var(--cyan)" stopOpacity="0.45" />
            <stop offset="1" stopColor="var(--cyan)" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="g-up" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="var(--magenta)" stopOpacity="0.45" />
            <stop offset="1" stopColor="var(--magenta)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={PAD_L} x2={W} y1={y(max * t)} y2={y(max * t)} className="chart__grid" />
            <text x={PAD_L - 6} y={y(max * t) + 3} textAnchor="end" className="chart__axis">{formatBitRate(max * t)}</text>
          </g>
        ))}
        <text x={PAD_L} y={H - 4} className="chart__axis">−60 s</text>
        <text x={W - 4} y={H - 4} textAnchor="end" className="chart__axis">now</text>
        <polygon points={area(down)} fill="url(#g-down)" />
        <polygon points={area(up)} fill="url(#g-up)" />
        <polyline points={line(down)} fill="none" stroke="var(--cyan)" strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
        <polyline points={line(up)} fill="none" stroke="var(--magenta)" strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
      </svg>
    </section>
  );
}

function TopConnections() {
  const flows = useApp((s) => s.flows);
  const selected = useApp((s) => s.selection.flowId);
  const top = useMemo(() => [...flows].sort((a, b) => b.bytes - a.bytes).slice(0, TOP_CONNECTIONS), [flows]);
  return (
    <section className="panel glass">
      <h4 className="panel__title">Top Connections</h4>
      <table className="mini-table">
        <thead>
          <tr>
            <th>Destination</th>
            <th>Protocol</th>
            <th className="num">Packets</th>
            <th className="num">Traffic</th>
          </tr>
        </thead>
        <tbody>
          {top.map((f) => {
            const style = VEHICLE_STYLES[f.class];
            return (
              <tr key={f.id} onClick={() => selectFlow(f.id)} className={f.id === selected ? "is-selected" : ""}>
                <td className="mono ellipsis" title={f.hostname ?? f.responder}>{f.hostname ?? f.responder}</td>
                <td>
                  <span className="badge" style={{ color: cssColor(style.color), borderColor: cssColor(style.color) }}>{style.label}</span>
                </td>
                <td className="num mono">{f.packets.toLocaleString()}</td>
                <td className="num mono">{formatBytes(f.bytes)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {top.length === 0 && <p className="muted pad">No active connections.</p>}
    </section>
  );
}

export function BottomPanels() {
  const stats = useApp((s) => s.stats);
  return (
    <footer className="bottom">
      <ProtocolDonut stats={stats} />
      <TrafficChart stats={stats} />
      <TopConnections />
    </footer>
  );
}
