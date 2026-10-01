import { api, insideDesktopShell, toCommandError } from "./ipc";
import { trafficBus } from "./trafficBus";
import { EMPTY_SELECTION, getApp, MAX_ALERTS, setApp } from "../stores/appStore";
import type { ReplayCommand, ReplayStatus, SessionInfo, StreamMessage } from "../types";

/** Messages from a superseded session's channel are ignored. */
let activeToken = 0;

function handlerFor(token: number) {
  return (msg: StreamMessage) => {
    if (token !== activeToken) return;
    switch (msg.type) {
      case "traffic":
        trafficBus.push(msg.events);
        break;
      case "stats":
        setApp({ stats: msg.stats, health: msg.health });
        break;
      case "flows":
        setApp({ flows: msg.flows });
        break;
      case "devices":
        setApp({ devices: msg.devices });
        break;
      case "alerts":
        setApp({ alerts: [...getApp().alerts, ...msg.alerts].slice(-MAX_ALERTS) });
        break;
      case "sourceEnded":
        setApp({
          phase: "ended",
          endedReason: msg.reason,
          error: msg.error ? { code: "captureFailed", message: msg.reason, hint: null } : getApp().error,
        });
        break;
    }
  };
}

function resetForNewSession() {
  trafficBus.clear();
  setApp({
    phase: "starting",
    error: null,
    endedReason: null,
    stats: null,
    health: null,
    flows: [],
    devices: [],
    alerts: [],
    alertsSeenId: 0,
    selection: EMPTY_SELECTION,
    focusFlowId: null,
    paused: false,
  });
}

export async function loadEnvironment(): Promise<void> {
  if (!insideDesktopShell()) return;
  try {
    const environment = await api.captureEnvironment();
    setApp({ environment });
    if (environment.driverAvailable) await refreshInterfaces();
  } catch (e) {
    setApp({ error: toCommandError(e) });
  }
}

export async function refreshInterfaces(): Promise<void> {
  try {
    const interfaces = await api.listInterfaces();
    const current = getApp().selectedInterfaceId;
    const keep = interfaces.some((i) => i.id === current);
    setApp({ interfaces, interfacesError: null, selectedInterfaceId: keep ? current : (interfaces[0]?.id ?? null) });
  } catch (e) {
    setApp({ interfaces: [], interfacesError: toCommandError(e) });
  }
}

export async function startLive(): Promise<void> {
  const { selectedInterfaceId, promiscuous, captureFilter } = getApp();
  if (!selectedInterfaceId) return;
  await start((onMessage) =>
    api.startLiveCapture({ interfaceId: selectedInterfaceId, promiscuous, captureFilter: captureFilter.trim() || null }, onMessage),
  );
}

export async function startDemo(): Promise<void> {
  await start((onMessage) => api.startDemo(getApp().demoRate, onMessage));
}

/** Opens the native file dialog and replays the chosen capture through the visualization. */
export async function openCaptureFile(): Promise<void> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const path = await open({
    multiple: false,
    directory: false,
    title: "Open capture file",
    filters: [{ name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] }],
  });
  if (typeof path !== "string") return;
  const ok = await start((onMessage) => api.openCaptureFile(path, onMessage));
  if (ok) setApp({ view: "global" });
}

/** Asks where to save, then writes the packets kept for the hex view as a pcap. */
export async function exportKeptPackets(): Promise<string | null> {
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({
    title: "Export kept packets",
    defaultPath: "packetcity-export.pcap",
    filters: [{ name: "Packet capture", extensions: ["pcap"] }],
  });
  if (!path) return null;
  try {
    const count = await api.exportPcap(path);
    return `Exported ${count.toLocaleString()} packets to ${path}`;
  } catch (e) {
    setApp({ error: toCommandError(e) });
    return null;
  }
}

async function start(begin: (onMessage: (msg: StreamMessage) => void) => Promise<SessionInfo>): Promise<boolean> {
  const token = ++activeToken;
  resetForNewSession();
  try {
    const session = await begin(handlerFor(token));
    if (token !== activeToken) return false;
    setApp({ session, phase: "running", replay: null });
    if (session.source === "replay") pollReplay(token);
    return true;
  } catch (e) {
    if (token === activeToken) setApp({ phase: "idle", session: null, error: toCommandError(e) });
    return false;
  }
}

const REPLAY_POLL_MS = 250;

function pollReplay(token: number): void {
  const tick = async () => {
    if (token !== activeToken || getApp().phase !== "running") return;
    try {
      const status = await api.replayStatus();
      if (token !== activeToken) return;
      applyReplayStatus(status);
    } catch {
      // Transient IPC errors are retried on the next tick.
    }
    window.setTimeout(tick, REPLAY_POLL_MS);
  };
  void tick();
}

function applyReplayStatus(status: ReplayStatus | null): void {
  const prev = getApp().replay;
  // A seek restarts the engine; vehicles and alerts from the old timeline no longer apply.
  if (status && prev && status.generation !== prev.generation) {
    trafficBus.clear();
    setApp({ selection: EMPTY_SELECTION, focusFlowId: null, alerts: [], alertsSeenId: 0 });
  }
  setApp({ replay: status });
}

export async function replayCommand(command: ReplayCommand): Promise<void> {
  try {
    applyReplayStatus(await api.replayControl(command));
  } catch (e) {
    setApp({ error: toCommandError(e) });
  }
}

export async function stopSession(): Promise<void> {
  try {
    await api.stopSession();
  } catch (e) {
    setApp({ error: toCommandError(e) });
  }
}

export function togglePause(): void {
  const paused = !getApp().paused;
  // Discard the backlog so resuming shows current traffic rather than a burst of stale events.
  if (!paused) trafficBus.clear();
  setApp({ paused });
}

export function selectVehicle(packetId: number, flowId: number | null): void {
  setApp({ selection: { packetId, flowId, node: null } });
}

export function selectFlow(flowId: number): void {
  setApp({ selection: { packetId: null, flowId, node: null }, focusFlowId: flowId });
}

export function selectNode(node: string): void {
  setApp({ selection: { packetId: null, flowId: null, node } });
}

export function clearSelection(): void {
  setApp({ selection: EMPTY_SELECTION, focusFlowId: null });
}
