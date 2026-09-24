import { insideDesktopShell } from "../services/ipc";
import { loadEnvironment } from "../services/session";
import { setApp, useApp } from "../stores/appStore";

/** Driver problems and command errors, in plain language with a next step. */
export function Notices() {
  const env = useApp((s) => s.environment);
  const error = useApp((s) => s.error);
  const interfacesError = useApp((s) => s.interfacesError);
  const endedReason = useApp((s) => s.endedReason);
  const phase = useApp((s) => s.phase);
  const linkDown = useApp((s) => !!s.health?.linkDown && s.session?.source === "live");

  if (!insideDesktopShell()) {
    return (
      <div className="notice notice--warn glass">
        <b>Running outside the desktop app.</b> Packet capture requires the PacketCity desktop shell — start it with{" "}
        <code>npm run dev</code>.
      </div>
    );
  }

  return (
    <>
      {env && !env.driverAvailable && (
        <div className="notice notice--warn glass">
          <b>Live capture unavailable.</b> {env.driverMessage}{" "}
          {env.platform === "windows" && (
            <>
              Install <b>Npcap</b> from npcap.com (keep “WinPcap API-compatible mode” checked). Demo mode still works.{" "}
            </>
          )}
          <button className="btn btn--ghost notice__action" onClick={() => void loadEnvironment()}>
            Retry
          </button>
        </div>
      )}
      {interfacesError && (
        <div className="notice notice--error glass">
          <b>Could not list interfaces.</b> {interfacesError.message} {interfacesError.hint}
        </div>
      )}
      {error && (
        <div className="notice notice--error glass" role="alert">
          <b>{error.message}</b> {error.hint}
          <button className="notice__close" onClick={() => setApp({ error: null })} aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}
      {linkDown && phase !== "ended" && (
        <div className="notice notice--warn glass" role="status">
          <b>Network link is down.</b> The interface reports no connection (cable unplugged or Wi-Fi disconnected). Capture
          resumes on its own when the link returns.
        </div>
      )}
      {phase === "ended" && endedReason && !error && <div className="notice glass">{endedReason}</div>}
    </>
  );
}
