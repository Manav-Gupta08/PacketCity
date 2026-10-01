import { Channel, invoke, isTauri } from "@tauri-apps/api/core";

import type {
  CaptureEnvironment,
  CommandError,
  FlowSnapshot,
  InterfaceInfo,
  LiveCaptureOptions,
  PacketRecord,
  ReplayCommand,
  ReplayStatus,
  SessionInfo,
  StreamMessage,
} from "../types";

export const insideDesktopShell = (): boolean => isTauri();

/** Normalises anything thrown by `invoke` into the backend's CommandError shape. */
export function toCommandError(err: unknown): CommandError {
  if (err && typeof err === "object" && "message" in err && "code" in err) {
    const e = err as Partial<CommandError>;
    return { code: String(e.code), message: String(e.message), hint: e.hint ?? null };
  }
  return { code: "ipc", message: err instanceof Error ? err.message : String(err), hint: null };
}

function channel(onMessage: (msg: StreamMessage) => void): Channel<StreamMessage> {
  const ch = new Channel<StreamMessage>();
  ch.onmessage = onMessage;
  return ch;
}

export const api = {
  captureEnvironment: () => invoke<CaptureEnvironment>("capture_environment"),
  listInterfaces: () => invoke<InterfaceInfo[]>("list_interfaces"),
  startLiveCapture: (options: LiveCaptureOptions, onMessage: (msg: StreamMessage) => void) =>
    invoke<SessionInfo>("start_live_capture", { options, onEvent: channel(onMessage) }),
  startDemo: (packetsPerSec: number, onMessage: (msg: StreamMessage) => void) =>
    invoke<SessionInfo>("start_demo", { packetsPerSec, onEvent: channel(onMessage) }),
  openCaptureFile: (path: string, onMessage: (msg: StreamMessage) => void) =>
    invoke<SessionInfo>("open_capture_file", { path, onEvent: channel(onMessage) }),
  replayControl: (command: ReplayCommand) => invoke<ReplayStatus>("replay_control", { command }),
  replayStatus: () => invoke<ReplayStatus | null>("replay_status"),
  stopSession: () => invoke<void>("stop_session"),
  getPacket: (id: number) => invoke<PacketRecord | null>("get_packet", { id }),
  getFlow: (id: number) => invoke<FlowSnapshot | null>("get_flow", { id }),
  setPayloadCapture: (enabled: boolean) => invoke<void>("set_payload_capture", { enabled }),
  getPacketBytes: (id: number) => invoke<number[] | null>("get_packet_bytes", { id }),
  exportPcap: (path: string) => invoke<number>("export_pcap", { path }),
};
