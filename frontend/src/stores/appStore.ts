import { create } from "zustand";

import type {
  Alert,
  CaptureEnvironment,
  CommandError,
  DeviceSnapshot,
  FlowSnapshot,
  InterfaceInfo,
  PipelineHealth,
  ReplayStatus,
  SessionInfo,
  StatsSnapshot,
} from "../types";

export type Phase = "idle" | "starting" | "running" | "ended";
export type View = "global" | "myTraffic" | "connections" | "devices" | "pcap" | "alerts" | "protocols" | "statistics" | "settings";

export interface RenderMetrics {
  fps: number;
  vehicles: number;
  waiting: number;
  mergedPackets: number;
  filteredPackets: number;
  offMapPackets: number;
}

/** What the details panel shows. A vehicle selection sets packet + flow; a building sets node. */
export interface Selection {
  packetId: number | null;
  flowId: number | null;
  node: string | null;
}

export const EMPTY_SELECTION: Selection = { packetId: null, flowId: null, node: null };
const DEFAULT_DEMO_RATE = 120;
export const DEMO_RATE_KEY = "packetcity.demoRate";

interface AppState {
  environment: CaptureEnvironment | null;
  interfaces: InterfaceInfo[];
  interfacesError: CommandError | null;
  selectedInterfaceId: string | null;
  promiscuous: boolean;
  captureFilter: string;

  phase: Phase;
  session: SessionInfo | null;
  error: CommandError | null;
  endedReason: string | null;

  stats: StatsSnapshot | null;
  health: PipelineHealth | null;
  flows: FlowSnapshot[];
  devices: DeviceSnapshot[];

  view: View;
  paused: boolean;
  vizFilter: string;
  search: string;
  selection: Selection;
  /** Flow whose vehicles are emphasised on the road. */
  focusFlowId: number | null;
  render: RenderMetrics;
  replay: ReplayStatus | null;
  /** Demo generator rate (packets/s); a Settings value used for load testing. */
  demoRate: number;
  alerts: Alert[];
  /** Highest alert id the user has seen on the Alerts page. */
  alertsSeenId: number;
  /** Raw bytes kept for the hex view; off at every launch. */
  payloadCapture: boolean;
}

export const useApp = create<AppState>(() => ({
  environment: null,
  interfaces: [],
  interfacesError: null,
  selectedInterfaceId: null,
  promiscuous: false,
  captureFilter: "",

  phase: "idle",
  session: null,
  error: null,
  endedReason: null,

  stats: null,
  health: null,
  flows: [],
  devices: [],

  view: "global",
  paused: false,
  vizFilter: "",
  search: "",
  selection: EMPTY_SELECTION,
  focusFlowId: null,
  render: { fps: 0, vehicles: 0, waiting: 0, mergedPackets: 0, filteredPackets: 0, offMapPackets: 0 },
  replay: null,
  demoRate: Number(localStorage.getItem(DEMO_RATE_KEY)) || DEFAULT_DEMO_RATE,
  alerts: [],
  alertsSeenId: 0,
  payloadCapture: false,
}));

export const MAX_ALERTS = 500;

export const setApp = useApp.setState;
export const getApp = useApp.getState;
