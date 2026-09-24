// Dev helper: screenshots the PacketCity webview via the WebView2 DevTools protocol.
// Requires the app to be started with WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222.
// Usage: node cdp-screenshot.mjs <out.png> [click:x,y | <js expression>]
import { writeFileSync } from "node:fs";

const port = process.env.CDP_PORT ?? "9222";
const out = process.argv[2] ?? ".deps/webview.png";
const expr = process.argv[3];

const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const page = targets.find((t) => t.type === "page");
if (!page) throw new Error("no webview page target");

const ws = new WebSocket(page.webSocketDebuggerUrl);
let id = 0;
const pending = new Map();
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  }
};
await new Promise((r) => (ws.onopen = r));
const send = (method, params = {}) =>
  new Promise((resolve) => {
    const n = ++id;
    pending.set(n, resolve);
    ws.send(JSON.stringify({ id: n, method, params }));
  });

const click = async (x, y) => {
  for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
    await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
  }
};
const panelOpen = async () =>
  (await send("Runtime.evaluate", { expression: "!!document.querySelector('.details')", returnByValue: true })).result?.result?.value;

if (expr?.startsWith("clickscan:")) {
  // Tries points on a small grid around (x, y) until the details panel opens.
  const [x, y, r = 24] = expr.slice(10).split(",").map(Number);
  let hit = null;
  outer: for (let dy = -r; dy <= r; dy += 4) {
    for (let dx = -r; dx <= r; dx += 4) {
      await click(x + dx, y + dy);
      if (await panelOpen()) {
        hit = [x + dx, y + dy];
        break outer;
      }
    }
  }
  console.log(hit ? `hit at ${hit}` : "no hit");
  await new Promise((res) => setTimeout(res, 500));
} else if (expr?.startsWith("click:")) {
  const [x, y] = expr.slice(6).split(",").map(Number);
  await click(x, y);
  await new Promise((r) => setTimeout(r, 400));
} else if (expr) {
  const res = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  console.log(JSON.stringify(res.result?.result?.value ?? res.result, null, 1));
}
const shot = await send("Page.captureScreenshot", { format: "png" });
writeFileSync(out, Buffer.from(shot.result.data, "base64"));
console.log(`saved ${out}`);
ws.close();
