import { useEffect, type ReactNode } from "react";

import { AlertsView } from "./components/AlertsView";
import { BottomPanels } from "./components/BottomPanels";
import { CityView } from "./components/CityView";
import { ConnectionsView } from "./components/ConnectionsView";
import { DetailsPanel } from "./components/DetailsPanel";
import { DevicesView } from "./components/DevicesView";
import { KpiBar } from "./components/KpiBar";
import { Notices } from "./components/Notices";
import { PcapView } from "./components/PcapView";
import { ProtocolsView } from "./components/ProtocolsView";
import { SettingsView } from "./components/SettingsView";
import { Sidebar } from "./components/Sidebar";
import { StatisticsView } from "./components/StatisticsView";
import { loadEnvironment } from "./services/session";
import { useApp, type View } from "./stores/appStore";

const PAGES: Partial<Record<View, () => ReactNode>> = {
  connections: () => <ConnectionsView />,
  devices: () => <DevicesView />,
  protocols: () => <ProtocolsView />,
  alerts: () => <AlertsView />,
  pcap: () => <PcapView />,
  statistics: () => <StatisticsView />,
  settings: () => <SettingsView />,
};

export function App() {
  const view = useApp((s) => s.view);
  const demo = useApp((s) => s.session?.source === "demo" && s.phase !== "idle");
  const cityVisible = view === "global" || view === "myTraffic";
  const page = PAGES[view];

  useEffect(() => {
    void loadEnvironment();
  }, []);

  return (
    <div className={`app ${demo ? "app--demo" : ""}`}>
      <Sidebar />
      <KpiBar />
      <main className="main">
        <Notices />
        <div className="stage">
          {/* One renderer serves both city views; it stays mounted so switching is instant. */}
          <div className="view" hidden={!cityVisible}>
            <CityView mode={view === "myTraffic" ? "personal" : "global"} visible={cityVisible} />
          </div>
          {page && <div className="view">{page()}</div>}
          <DetailsPanel />
        </div>
      </main>
      <BottomPanels />
    </div>
  );
}
