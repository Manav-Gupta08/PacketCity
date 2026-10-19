import { useState } from "react";

import { replayCommand } from "../services/session";
import { useApp } from "../stores/appStore";
import { Icon } from "./Icon";

const PRESET_SPEEDS = [1, 2, 5, 10];
const MIN_SPEED = 0.1;
const MAX_SPEED = 100;

function clock(us: number): string {
  const s = Math.max(0, Math.floor(us / 1_000_000));
  const h = Math.floor(s / 3600);
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

export function ReplayBar() {
  const status = useApp((s) => s.replay);
  const info = useApp((s) => s.session?.replay);
  const [drag, setDrag] = useState<number | null>(null);
  const [custom, setCustom] = useState("");
  if (!status || !info) return null;

  const duration = Math.max(1, status.endUs - status.startUs);
  const pos = (drag ?? status.positionUs) - status.startUs;
  const seek = (offset: number) => void replayCommand({ action: "seek", positionUs: Math.round(status.startUs + offset) });
  const applyCustom = () => {
    const v = Number(custom);
    if (Number.isFinite(v) && v >= MIN_SPEED && v <= MAX_SPEED) void replayCommand({ action: "speed", value: v });
    setCustom("");
  };

  return (
    <div className="replay glass" aria-label="Replay controls">
      <button
        className="btn btn--primary replay__play"
        onClick={() => void replayCommand({ action: status.playing ? "pause" : "play" })}
        aria-label={status.playing ? "Pause replay" : "Play replay"}
      >
        <Icon name={status.playing ? "pause" : "play"} size={15} />
      </button>
      <span className="replay__time mono">
        {clock(pos)} / {clock(duration)}
      </span>
      <input
        className="replay__timeline"
        type="range"
        min={0}
        max={duration}
        step={Math.max(1, Math.round(duration / 1000))}
        value={pos}
        onChange={(e) => setDrag(status.startUs + Number(e.target.value))}
        onPointerUp={() => {
          if (drag !== null) seek(drag - status.startUs);
          setDrag(null);
        }}
        onKeyUp={(e) => {
          if (e.key.startsWith("Arrow") || e.key === "Home" || e.key === "End") seek(Number(e.currentTarget.value));
          setDrag(null);
        }}
        aria-label="Replay position"
      />
      <div className="replay__speeds" role="group" aria-label="Replay speed">
        {PRESET_SPEEDS.map((s) => (
          <button key={s} className={`chip ${Math.abs(status.speed - s) < 0.001 ? "is-on" : ""}`} onClick={() => void replayCommand({ action: "speed", value: s })}>
            {s}×
          </button>
        ))}
        <input
          className="replay__custom mono"
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyCustom()}
          onBlur={applyCustom}
          placeholder={PRESET_SPEEDS.includes(status.speed) ? "custom" : `${status.speed}×`}
          aria-label={`Custom speed (${MIN_SPEED}–${MAX_SPEED})`}
        />
      </div>
      <span className="replay__file" title={info.fileName}>
        {status.finished ? "End of capture" : info.fileName}
      </span>
    </div>
  );
}
