# PacketCity

**A desktop network packet analyzer that turns real captured traffic into a living cyberpunk city.**
Every packet is a futuristic car, every connection a stream of traffic, the router a highway
interchange, your LAN devices buildings, and the internet a highway disappearing into the haze.
Everything you see is driven by real packets. Click any car to inspect the packet behind it.

Rust (capture + analysis) · Tauri 2 · React + TypeScript · Three.js (WebGL2)

## Features

- **Live capture** on any interface (Npcap / libpcap), with BPF capture filters and promiscuous
  mode, plus a clear *capture scope* banner saying what this interface can and cannot see.
- **Live Traffic (Global city)**: your device, the router interchange, LAN devices (named from
  DHCP/mDNS/LLMNR/NetBIOS, labelled with their manufacturer), the broadcast plaza, the internet
  gateway, and towers for the busiest remote hosts. Traffic drives between them.
- **My Traffic**: a two-carriageway highway between your device and the internet: incoming on
  one side, outgoing on the other.
- **Protocol → vehicle**: HTTPS coupes, TCP/HTTP sedans, UDP compacts, DNS bikes, ICMP
  interceptors, ARP/DHCP vans; merged bursts become haulers ([mapping](docs/VISUAL_MAPPING.md)).
- **Inspector**: packet layers (Ethernet, ARP, IPv4/6, TCP/UDP/ICMP, DNS, DHCP, NetBIOS, TLS
  SNI, HTTP), flow statistics and TCP state, device details, "follow connection".
- **Connections, Devices, Protocols, Statistics** pages; **Alerts** for port scans, host sweeps,
  duplicate IPs, new devices, retransmission storms and malformed bursts.
- **PCAP / PCAPNG replay** with pause, 0.1–100× speed and seek.
- **Hostnames everywhere**: TLS SNI (reassembled across segments), HTTP Host, and DNS-answer
  labels for QUIC and other unnamed flows.
- **Built for load**: bounded queues end to end, convoy aggregation, instanced rendering with LOD,
  adaptive quality. Around 400k pkt/s engine throughput on one core.
- **Private by design**: no telemetry and no network access besides capture. By default no
  payload bytes are stored; an explicit, off-by-default switch keeps recent packet bytes in memory
  for a hex view.

## Getting started

### Prerequisites

|              | Windows                                                                                                   | Linux                                                                                       | macOS                                              |
| ------------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Build        | Rust ≥ 1.80 (MSVC), VS Build Tools (C++), Node 20+, Npcap**SDK** (`scripts/fetch-npcap-sdk.ps1`) | Rust, Node,`libpcap-dev`, [Tauri deps](https://tauri.app/start/prerequisites/) (WebKitGTK) | Rust, Node, Xcode CLT                              |
| Live capture | [Npcap](https://npcap.com) with "WinPcap API-compatible mode"                                              | `sudo setcap cap_net_raw,cap_net_admin=eip <binary>`                                      | Access to`/dev/bpf*` (e.g. Wireshark's ChmodBPF) |

Without a capture driver the app still starts and explains what is missing; the clearly labelled
**Demo** mode (synthetic traffic, documentation-range addresses) and **PCAP replay** work anywhere.
Npcap's licence does not allow bundling it, so the Windows installer only checks for it and offers
the official download page.

### Build and run

```powershell
npm install
powershell -File scripts/fetch-npcap-sdk.ps1   # Windows only, once
npm run dev                                    # desktop app with hot reload
npm run build                                  # release build + installer (Windows: target/release/bundle/nsis/)
```

### Tests and tools

```powershell
npm test                                       # frontend unit tests (vitest)
npm run typecheck
cargo test --workspace                         # Rust unit + integration tests
cargo clippy --workspace --all-targets
cargo run -p packetcity-capture --example probe -- 10 "" "" out.pcap   # headless capture: secs iface bpf [save]
cargo run --release -p packetcity-core --example stress                # performance harness
cargo run -p packetcity-core --example make_fixtures                   # regenerate tests/fixtures
node scripts/generate-oui.mjs                                          # refresh the MAC vendor table (IEEE)
```

## Project layout

| Path                   | What it is                                                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `core/`              | Parsing, flows, devices, alerts, statistics, event batching, PCAP reader/replay. No driver dependency, fully unit-tested |
| `capture/`           | Interface discovery, live capture thread, driver statistics, interface watch                                             |
| `desktop/src-tauri/` | Tauri shell: commands, sessions, installer hooks                                                                         |
| `frontend/`          | React UI and the Three.js city (`src/visualization/`)                                                                  |
| `docs/`              | [Architecture](docs/ARCHITECTURE.md) and [visual mapping](docs/VISUAL_MAPPING.md)                                          |
| `tests/fixtures/`    | Deterministic reference captures used by integration tests                                                               |
| `scripts/`           | SDK fetch, icon and vendor-table generators, UI automation helpers for development                                       |

## Remaining work

- **Linux and macOS**: `core` and `capture` type-check for both, but live capture has not been
  verified on those systems, and their bundles (AppImage/deb, dmg) must be built there.
- **Code signing** for the Windows installer.
- **Export to PCAP from the UI** (possible for the opt-in packet-byte ring; not built yet).
- **Elevated road sections**: the city's roads are all at ground level; ramps and flyovers need
  height support in the road model.

### Known limitations

- The Global view can only show what the capture interface receives (see the Capture Scope banner):
  on switched networks that is mostly your own traffic plus broadcasts.
- In live mode statistics use wall-clock time; bursts arriving more than 60 s late count only
  toward totals.
- Loopback traffic has no place on the Global map (counted as "off-map"); it drives the outgoing
  side of My Traffic.

## Acknowledgements

MAC vendor names come from the public [IEEE MA-L registry](https://standards-oui.ieee.org/).
Packet capture uses [Npcap](https://npcap.com) / libpcap, which is installed separately.

## Author

**Manav Gupta**

CyberSecurity Student | Software Developer | Backend Engineer

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Manav Gupta.
