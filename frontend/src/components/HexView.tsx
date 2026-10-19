import { useEffect, useState } from "react";

import { hexDump } from "../format";
import { api } from "../services/ipc";
import { setApp, useApp } from "../stores/appStore";

/** Raw bytes of one packet, fetched only when the section is opened. */
export function HexSection({ id }: { id: number }) {
  const enabled = useApp((s) => s.payloadCapture);
  const [open, setOpen] = useState(false);
  const [bytes, setBytes] = useState<number[] | null | undefined>(undefined);

  useEffect(() => {
    setBytes(undefined);
    if (!open) return;
    let cancelled = false;
    api
      .getPacketBytes(id)
      .then((b) => !cancelled && setBytes(b))
      .catch(() => !cancelled && setBytes(null));
    return () => {
      cancelled = true;
    };
  }, [id, open, enabled]);

  return (
    <details className="details__section" onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>Bytes</summary>
      {bytes === undefined && open && <p className="muted">Loading…</p>}
      {bytes === null && (
        <p className="muted">
          Not kept. Packet bytes are stored only while <b>Packet bytes (hex view)</b> is on in{" "}
          <button className="linklike" onClick={() => setApp({ view: "settings" })}>Settings</button>, and only for recent packets.
        </p>
      )}
      {bytes && <pre className="details__code details__hex mono">{hexDump(bytes)}</pre>}
    </details>
  );
}
