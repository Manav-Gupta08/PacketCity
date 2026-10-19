# PacketCity — Architecture

PacketCity is a desktop packet analyzer whose primary view renders real traffic as vehicles on a
cyberpunk road network. Data correctness comes first; the visualization is a view over it.

## Components

```
┌──────────────────────────── desktop (Tauri, Rust) ─────────────────────────────┐
│                                                                                │
│  capture thread            pipeline thread (per session)          commands     │
│  ───────────────           ─────────────────────────────          ────────     │
│  libpcap / Npcap  ──RawFrame──►  Engine ──► TrafficBatch ──┐     get_packet    │
│  (packetcity-capture)  bounded   parse → classify →        │     get_flow      │
│  or DemoGenerator      channel   direction → flow →        │     list_ifaces   │
│  (packetcity-core)     drop-on-  stats → event batch       │         ▲         │
│                        full      + PacketStore ring        │         │ lock    │
│                                  Arc<Mutex<Engine>> ───────┼─────────┘         │
│                                                            ▼                   │
│                                      Tauri Channel<StreamMessage> (ordered)    │
└────────────────────────────────────────────────────────────┬───────────────────┘
                                                             │ traffic 20 Hz
                                                             │ stats 2 Hz, flows 1 Hz
┌──────────────────────────── frontend (React + Three.js) ───▼───────────────────┐
│  session.ts ─► TrafficBus (bounded ring) ─► CityRenderer (Three.js, WebGL2)    │
│           └──► zustand store (stats, flows, session, selection) ─► React panels│
│  ConvoyStaging → RoutePool (struct-of-arrays, fixed capacity) → instanced cars  │
└────────────────────────────────────────────────────────────────────────────────┘
```

| Crate / folder | Responsibility | Depends on libpcap? |
|---|---|---|
| `core/` (`packetcity-core`) | Frame parsing, classification, direction, flows, devices, alerts, statistics, event batching, packet ring store, pipeline loop, demo generator, PCAP/PCAPNG reader/writer and replay, byte-exact frame builders for tests | **No** — fully testable without drivers |
| `capture/` (`packetcity-capture`) | Interface discovery, live capture thread, BPF capture filters, error classification, per-OS driver loading | Yes |
| `desktop/src-tauri/` | Tauri shell: commands, session lifecycle, IPC channel sink, capture-scope text | via capture |
| `frontend/` | UI, visualization engine, stores, IPC client | — |

## Data model (separated on purpose)

| Type | Meaning | Lifetime |
|---|---|---|
| `RawFrame` | Bytes + timestamp from any source | Transient |
| `ParsedPacket` / `PacketRecord` | Header metadata of one packet; **no payload bytes** | Ring buffer (`PacketStore`, 50k) |
| `Flow` / `FlowSnapshot` | Bidirectional 5-tuple aggregate: counters, TCP state, retransmissions, hostname | Until idle timeout / capacity eviction |
| "Connection" | A TCP flow in `Established` state (counted in stats) | — |
| `TrafficEvent` | Visualization unit: one packet, or a merged per-flow convoy under load | One batch |
| Device | LAN host learned from traffic (MAC-keyed; IP only on MAC-less links), with sent/received counters | Table of ≤256 per session |
| Node | Map endpoint of an event: `self`, `gateway`, `internet`, `broadcast`, `dev:<id>`, `lan` (untracked) | Per event |

## Networking logic worth knowing

- **Direction** (`core/src/direction.rs`): "this host" = the capture interface's IP addresses.
  Source local → Outgoing; destination local, or broadcast/multicast received → Incoming; both →
  Local (loopback); neither → Transit (SPAN/mirror or shared medium). Our MAC is learned from frames
  sourced by our IP so non-IP frames resolve too.
- **Flow key** (`core/src/flows/key.rs`): endpoints stored sorted, so A→B and B→A share a key. ARP
  keys on protocol addresses; other non-IP frames on MACs + EtherType; IP without a parsed transport
  header (other protocols, non-first fragments) becomes `OtherIp(proto)` rather than polluting a
  TCP/UDP flow.
- **Initiator**: first packet's source, except: a SYN-ACK seen first flips it, and when joining
  mid-stream a packet from a service port (≤1023, or below the 49152 ephemeral range) to a client
  port is attributed to the responder.
- **TCP tracking** (`core/src/flows/tcp.rs`): passive observer approximation. Retransmission =
  segment whose sequence end does not advance past the highest end already seen in that direction
  (RFC 1982 serial arithmetic handles wraparound). Keep-alives are counted too — documented heuristic.
- **Port reuse**: a bare SYN on a Closed/Reset flow starts a new flow.
- **Timeouts** (packet time, so PCAP replay is consistent): TCP 300 s, TCP closed/reset 10 s,
  UDP 60 s, other 30 s. Hard cap 65 536 flows (oldest evicted).
- **Application identification**: payload signatures first (TLS record header + ClientHello SNI,
  HTTP/1.x request/status line + Host), port numbers only as hints. A ClientHello that spans
  several TCP segments (post-quantum key shares, randomised extension order) is reassembled by
  `flows/sni.rs`: in-order client segments of that one record only, ≤ 18 KiB, ≤ 64 flows at once,
  16 segments or 10 s max; the buffer is dropped once the SNI is read.
- **DNS names** (`core/src/names.rs`): A/AAAA answers of unicast DNS responses fill an
  IP→query-name map (4 096 entries, oldest evicted). Flows without an in-band name are labelled
  from it (`hostnameSource: "dnsAnswer"`, shown as "via DNS"); a later SNI/Host always wins.
  mDNS/LLMNR answers are ignored because they name LAN hosts, not destinations.
- **Statistics**: 60 one-second buckets; rates average the last 2 *completed* seconds; packets older
  than the window count only toward totals.
- **Devices & nodes** (`core/src/devices.rs`): on-link = inside an interface subnet (from its
  netmask) or link-local. Off-link endpoints are the `internet` node. The gateway is the MAC our
  unicast off-link traffic is sent to / arrives from, chosen by majority vote so broadcasts from
  misconfigured hosts can't claim it. Frames to broadcast/multicast MACs go to the `broadcast`
  node, so ARP requests never invent devices. Two hosts claiming one IP stay separate (MAC is
  identity) and get MAC-suffixed labels.
- **Device names** (`DeviceTable::learn_names`): only names hosts announce about themselves, by
  strength: DHCP host name option (client messages, keyed by `chaddr`) > mDNS A/AAAA records
  (answer *and* additional sections, `.local` stripped) > LLMNR > NetBIOS registrations and
  self-answers (workstation/server names, not groups). A weaker source never overwrites a stronger
  one. **Vendor** comes from the MAC prefix via the IEEE MA-L registry embedded as
  `core/data/oui.tsv` (`node scripts/generate-oui.mjs` refreshes it); locally administered
  (randomised) MACs are labelled as such instead of guessed.
- **Alerts** (`core/src/alerts.rs`): rule-based, over metadata only: port scan (≥20 ports on one
  host in 10 s), host sweep (≥20 on-link hosts on one port), duplicate IP (one IP, two MACs), new
  device (after a 60 s warm-up), retransmissions (≥10 % of ≥50 packets), malformed burst,
  brute force (≥15 new connections from one source to SSH/Telnet/FTP/RDP/VNC on one host in 60 s;
  mail, SMB and database ports are excluded because clients pool connections), DNS tunnelling (a
  query label ≥40 characters with ≥3.6 bits/char entropy). Each
  (rule, subject) pair has a 5-minute cooldown. These are hints, not an IDS.
- **Threat marking** (`core/src/threats.rs`): per-packet verdict carried on events, packet records
  and flows (stealth-scan flags, LAND, backdoor ports, DNS-tunnel names, and senders recently
  flagged as scanners or brute-forcers). The UI paints these vehicles red (orange for DNS tunnels).

## PCAP replay

- `core/src/capture_file.rs`: pure-Rust reader (no driver). PCAP in both byte orders, µs and ns;
  PCAPNG SHB/IDB/EPB/SPB/obsolete PB, multiple sections, `if_tsresol`. Records >256 KiB and blocks
  >16 MiB are rejected, so a hostile file cannot force large allocations. Frames on interfaces
  whose link type differs from the first are skipped and counted.
- `replay::analyze` infers the capturing host (busiest private IP) and its subnet (ARP neighbours,
  clamped to /16–/24, default /24) so direction and the Global map work as in live mode.
- `replay::run_replay` paces frames by packet timestamps (`ClockMode::PacketTime`); idle gaps are
  capped at 2 s; play/pause/speed (0.1–100×)/seek via `ReplayControl`. A seek resets the engine and
  bumps `generation`, which makes the UI clear vehicles and alerts from the old timeline. Replay
  uses a blocking send, so no frames are dropped.
- Fixtures in `tests/fixtures/` are generated from `core/src/reference.rs` and asserted by
  `core/tests/reference_capture.rs` (same results from pcap and pcapng, deterministic across runs).

## Visualization engine

Both views share one 3D renderer. The layout and traffic model are pure data
(`frontend/src/visualization/iso/`, `scenes/`); `visualization/three/` turns them into a city:

| Module | Role |
|---|---|
| `iso/scene.ts` | Scene model (roads, plazas, buildings, signs, flow tints, optional road elevation profiles) and `route(event)` contract; `groundHeightFn` gives the road surface height anywhere |
| `scenes/globalScene.ts` | City layout from the device list; paths joined at shared junctions |
| `scenes/personalScene.ts` | Two-carriageway highway; direction → carriageway, flow → lane |
| `iso/routes.ts` | Right-hand lane offset polylines with mitered corners; sampling with exact heading |
| `iso/RoutePool.ts` | Fixed-capacity struct-of-arrays vehicles; on-ramp gating; car-following (`FOLLOW_GAP`); accelerate/brake easing |
| `three/vehicles.ts` | Procedural cars: extruded side profiles + glass, wheels, lights, merged per model with per-vertex part materials (paint / glass / rubber / chrome / emissive) in one patched `MeshStandardMaterial`; low-poly impostors for LOD |
| `three/fleet.ts` | Pool → instanced meshes (one draw call per model × LOD), smoothed steering, fade/focus dimming, road light wash (one additive instanced mesh) |
| `three/buildings.ts` | Landmarks (YOUR DEVICE beacon tower, router control tower with halo rings, internet gateway arch + globe + megatowers, LAN facilities, remote-host spires) and varied decor (setback towers, LED slabs, billboards, data centres, twin towers); background district |
| `three/roads.ts` | Wet asphalt, lane markings, medians, barriers with light strips, lamp posts with light pools, directional arrows + lane lighting, gantries, roundabout; elevated roads are segmented and lifted onto a pillared deck |
| `three/environment.ts` | Sky gradient, exponential fog, neon PMREM environment map, skyline ring, rain, lights |
| `three/textures.ts` | Canvas-generated facade (albedo + lit windows), asphalt, wetness, billboard art |
| `iso/CityRenderer.ts` | WebGL renderer, bloom composer, map controls, landmark-fitting camera search, picking, projected holographic labels, adaptive quality, metrics |

Facade UVs are world-space, so one tiling window texture fits every building; geometry is merged
per material (a few dozen draw calls for the whole city). Labels are DOM elements projected from
their 3D anchor every frame. The default camera is found by searching poses that keep YOUR
DEVICE, the router, the internet gate, the far LAN device and the broadcast plaza on screen.
The background district, skyline and ground depend only on the road layout and are cached; a
device/destination change rebuilds just the network city (~60 ms).

**Destination towers** (`visualization/destinations.ts`): the busiest named internet destinations
(TLS SNI / HTTP Host / DNS-answer labels) get amber towers — 6 beside the Global internet
highway, 4 along My Traffic. A shown tower stays while it ranks in the top 2n (hysteresis), and
the set is name-sorted, so towers don't swap places every second. In the Global city, vehicles
whose `host` has a tower take that tower's exit instead of driving to the INTERNET gate.

**Elevation**: routes stay 2D. A road may carry an elevation profile (height, ramp-in, ramp-out
lengths, smoothstep ramps); the renderer lifts every vertex of that road to the profile height at
its position, and vehicles query `groundHeightFn` each frame for their height and pitch (slope
sampled ±4 units along the heading). The Global internet highway rises out of the interchange
onto a flyover over a ground-level cross street; destination exits are level skybridges.

## Performance & backpressure

| Stage | Bound | Overload behaviour |
|---|---|---|
| Capture → pipeline | 4 096-frame channel | `try_send`; drops counted (`framesDropped`), capture never blocks |
| Driver | 8 MiB kernel buffer | Drops read via `pcap_stats` every second (`driverDropped`, `interfaceDropped`) |
| Pipeline → UI | 20 Hz batches, ≤256 individual events + ≤128 per-flow aggregates | Extra packets merged into aggregates; counts exact |
| UI bus | 2 048 events | Oldest dropped (counted) — only when renderer paused/overloaded |
| Road | ≤400 intake and ≤30 spawns/frame, on-ramp spacing, 1 200-vehicle pool | Waiting events merge per flow into bigger "convoys" (`ConvoyStaging`) |

No per-frame allocation in the renderer: instance buffers are sized to the pool; the pool uses
typed arrays and a free list. Cars beyond 460 units use ~100-triangle impostors. On weak GPUs the
renderer drops rain, then bloom, after ~3 s below 40 FPS. React never sees per-packet data; only
2 Hz stats and 1 Hz flow/device lists.

Measured on an Intel HD 530 (1212×554 canvas): ~50 FPS with live Wi-Fi traffic; ~40 FPS with 550
cars on screen from the 5 000 pkt/s demo, rain and bloom on.

### Measured (`cargo run --release -p packetcity-core --example stress`)

Windows 11 laptop, release build, demo traffic mix, 6 s per rate:

| Offered | Processed | Drops | Max queue | Mean latency (worst 0.5 s) | Vehicle events/s |
|---|---|---|---|---|---|
| engine only, one core | ~406 000 pkt/s (2.4 Gbit/s) | — | — | — | — |
| 100 pkt/s | all | 0 | 0 | 0.20 ms | 136 |
| 1 000 pkt/s | all | 0 | 0 | 0.44 ms | 1 397 |
| 10 000 pkt/s | all | 0 | 0 | 0.32 ms | 5 266 |
| 100 000 pkt/s | ~95 600 pkt/s | 2 785 (≈3 %) | 3 262 | 12.3 ms | 7 020 |

("Processed" is slightly above "offered" at low rates because the demo generator emits whole
exchanges, such as a DNS query plus its answer.) The UI's load is set by vehicle events, not packets, and
the batcher caps it at ~7k/s; beyond 10k pkt/s traffic becomes bigger convoys, not more cars.
Live FPS, queue depth, drops and capture latency are on the Statistics page.

## Capture filter vs visualization filter

- **Capture filter**: BPF string compiled by libpcap in the driver. Requires restarting capture.
- **View filter** (`frontend/src/visualization/filter.ts`): client-side predicate over events;
  hides vehicles only. Statistics and flows are unaffected.

## Platform notes

| OS | Library | Runtime requirement | Permissions |
|---|---|---|---|
| Windows | Npcap `wpcap.dll` (delay-loaded) | [Npcap](https://npcap.com) installed | Admin only if Npcap was installed with "restrict to Administrators" |
| Linux | libpcap | `libpcap` package | `sudo setcap cap_net_raw,cap_net_admin=eip <binary>` |
| macOS | libpcap (system) | — | Access to `/dev/bpf*` (Wireshark ChmodBPF) or elevated run |

On Windows the executable links `wpcap.dll` with `/DELAYLOAD`, and `packetcity-capture` loads it by
absolute path from `System32\Npcap` (or `System32` in WinPcap-compatible mode) before any pcap
call. The app therefore starts without Npcap and explains how to fix it. The Npcap SDK is required
only to *build* (`scripts/fetch-npcap-sdk.ps1`).

**Interface watch**: a helper thread re-lists adapters every 2 s. An adapter missing from two
consecutive listings ends capture with `interfaceRemoved`; a "disconnected" connection status sets
`linkDown`, which the UI shows as a banner while capture continues. The watcher holds only the
counters, never a frame sender, so it cannot keep the pipeline alive.

**Linux/macOS**: `core` and `capture` type-check for `x86_64-unknown-linux-gnu` and
`aarch64-apple-darwin`; a live capture on those systems has not been verified yet.

**Packaging**: `npm run build` produces a per-user NSIS installer. Npcap cannot be redistributed,
so `desktop/src-tauri/windows/installer-hooks.nsh` checks for it after install and offers the
official download page. WebView2 is fetched by the Tauri bootstrapper if missing.

`.cargo/config.toml` pins `LIBPCAP_VER`. Without it the `pcap` crate probes the build machine and,
if no libpcap is found, compiles against the 1.0 API, which silently disables real immediate mode
(observed: ~43 ms vs 0.1 ms mean capture latency).

## Privacy

- No network access besides capture; no telemetry; no cloud services.
- By default payload bytes are not stored. Parsed metadata that comes from payloads is limited to: DNS
  question name/type and answer addresses, DHCP client MAC/host name, NetBIOS names, TLS SNI,
  HTTP method/path **without query string**/Host/status. Hostnames are sanitized to hostname
  characters. The only payload buffered by default is a split TLS ClientHello (handshake
  metadata, not application data), held until its SNI is read (≤ 10 s).
- **Opt-in packet bytes** (Settings → "Packet bytes (hex view)"): keeps raw frames (≤ 1 514 B each)
  of the last 5 000 packets in memory for the hex view. Off at every launch, never persisted or
  written to disk; turning it off drops the ring immediately. A replay seek keeps the setting.
- Capture state, interface and scope are always visible in the UI; demo sessions are labelled and
  use RFC 5737 documentation addresses only.
- Tauri capability `default.json` grants only `core:default` and `dialog:allow-open` (the PCAP
  picker); CSP forbids remote origins. `open_capture_file` accepts only absolute paths to regular
  `.pcap`/`.pcapng`/`.cap` files.
