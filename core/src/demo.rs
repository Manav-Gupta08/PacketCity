//! DEMO MODE traffic generator. Produces synthetic but byte-valid frames that travel through the
//! exact same parser/flow/event pipeline as real traffic. All addresses come from reserved
//! documentation ranges (RFC 5737 / RFC 3849) so demo data can never be mistaken for a real host.
//! The UI must label sessions using this source as DEMO.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::devices::LocalNetwork;
use crate::engine::EngineConfig;
use crate::frame::{LinkType, RawFrame};
use crate::packet::{MacAddr, TcpFlags};
use crate::pipeline::{wall_clock_us, FrameSender};
use crate::synth::{self, Endpoints};

pub const DEMO_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
pub const DEMO_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const DEMO_BROADCAST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 255);
const DEMO_LOCAL_MAC: MacAddr = MacAddr([0x02, 0xDE, 0x00, 0x00, 0x00, 0x20]);
const DEMO_GATEWAY_MAC: MacAddr = MacAddr([0x02, 0xDE, 0x00, 0x00, 0x00, 0x01]);
const REMOTES: [(Ipv4Addr, &str); 5] = [
    (Ipv4Addr::new(198, 51, 100, 10), "video.demo.example"),
    (Ipv4Addr::new(198, 51, 100, 24), "api.demo.example"),
    (Ipv4Addr::new(203, 0, 113, 7), "cdn.demo.example"),
    (Ipv4Addr::new(203, 0, 113, 80), "mail.demo.example"),
    (Ipv4Addr::new(198, 51, 100, 99), "updates.demo.example"),
];
const DNS_SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 53);
/// Demo LAN hosts: (address, MAC last octet).
const LAN_PEERS: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(192, 0, 2, 33), 0x33),
    (Ipv4Addr::new(192, 0, 2, 40), 0x40),
    (Ipv4Addr::new(192, 0, 2, 41), 0x41),
    (Ipv4Addr::new(192, 0, 2, 50), 0x50),
];
const DEMO_PREFIX: u8 = 24;
/// Hostile actors for the threat-marking showcase: a LAN scanner and an internet C2 host.
const DEMO_SCANNER: (Ipv4Addr, u8) = (Ipv4Addr::new(192, 0, 2, 66), 0x66);
const DEMO_C2: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 66);
const SCAN_BURST: u16 = 24;
const TICK: Duration = Duration::from_millis(10);
const MSS: usize = 1400;

pub fn demo_engine_config() -> EngineConfig {
    EngineConfig::new(LinkType::Ethernet, vec![IpAddr::V4(DEMO_LOCAL_IP)], vec![IpAddr::V4(DEMO_BROADCAST_IP)])
        .with_networks(vec![LocalNetwork { addr: IpAddr::V4(DEMO_LOCAL_IP), prefix: DEMO_PREFIX }])
}

fn peer_mac(last: u8) -> MacAddr {
    MacAddr([0x02, 0xDE, 0x00, 0x00, 0x00, last])
}

/// Small deterministic PRNG (xorshift64*) so demo runs are reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

pub struct DemoGenerator {
    rng: Rng,
    seq: u32,
    dns_id: u16,
    ports: [u16; REMOTES.len()],
    opened: [bool; REMOTES.len()],
}

impl DemoGenerator {
    pub fn new(seed: u64) -> Self {
        Self { rng: Rng(seed | 1), seq: 1, dns_id: 1, ports: [0; REMOTES.len()], opened: [false; REMOTES.len()] }
    }

    fn local_to(ip: Ipv4Addr, mac: MacAddr) -> Endpoints {
        Endpoints { src_mac: DEMO_LOCAL_MAC, dst_mac: mac, src_ip: IpAddr::V4(DEMO_LOCAL_IP), dst_ip: IpAddr::V4(ip) }
    }

    /// Appends one "scenario step" worth of frames (1..~6 packets) at timestamp `ts`.
    pub fn step(&mut self, ts: u64, out: &mut Vec<RawFrame>) {
        let push = |out: &mut Vec<RawFrame>, data: Vec<u8>| {
            out.push(RawFrame { timestamp_us: ts, wire_len: data.len() as u32, data });
        };
        self.seq = self.seq.wrapping_add(MSS as u32);
        let roll = self.rng.below(100);

        if roll < 55 {
            let i = self.rng.below(REMOTES.len() as u64) as usize;
            let (ip, host) = REMOTES[i];
            let ep = Self::local_to(ip, DEMO_GATEWAY_MAC);
            if !self.opened[i] || self.rng.chance(1) {
                self.opened[i] = true;
                self.ports[i] = 49152 + self.rng.below(16000) as u16;
                push(out, synth::tcp_frame(&ep, self.ports[i], 443, self.seq, 0, TcpFlags::SYN, b""));
                push(out, synth::tcp_frame(&ep.reversed(), 443, self.ports[i], 7, self.seq + 1, TcpFlags::SYN | TcpFlags::ACK, b""));
                push(out, synth::tcp_frame(&ep, self.ports[i], 443, self.seq + 1, 8, TcpFlags::ACK | TcpFlags::PSH, &synth::tls_client_hello(host)));
                return;
            }
            let burst = 1 + self.rng.below(4);
            for _ in 0..burst {
                let size = if self.rng.chance(70) { MSS } else { 100 + self.rng.below(900) as usize };
                push(out, synth::tcp_frame(&ep.reversed(), 443, self.ports[i], self.seq, 1, TcpFlags::ACK, &synth::tls_application_data(size)));
            }
            push(out, synth::tcp_frame(&ep, self.ports[i], 443, 1, self.seq, TcpFlags::ACK, b""));
        } else if roll < 70 {
            let ep = Self::local_to(REMOTES[0].0, DEMO_GATEWAY_MAC);
            let size = 900 + self.rng.below(300) as usize;
            push(out, synth::udp_frame(&ep.reversed(), 443, 50443, &vec![0x40; size]));
            if self.rng.chance(30) {
                push(out, synth::udp_frame(&ep, 50443, 443, &[0x40; 40]));
            }
        } else if roll < 80 {
            let (_, host) = REMOTES[self.rng.below(REMOTES.len() as u64) as usize];
            let ep = Self::local_to(DNS_SERVER, DEMO_GATEWAY_MAC);
            let port = 40000 + self.rng.below(20000) as u16;
            self.dns_id = self.dns_id.wrapping_add(1);
            push(out, synth::udp_frame(&ep, port, 53, &synth::dns_query(self.dns_id, host, 1)));
            push(out, synth::udp_frame(&ep.reversed(), 53, port, &synth::dns_response_a(self.dns_id, host, REMOTES[0].0)));
        } else if roll < 85 {
            let ep = Self::local_to(DEMO_GATEWAY_IP, DEMO_GATEWAY_MAC);
            push(out, synth::icmp_echo_frame(&ep, true, 1, self.dns_id));
            push(out, synth::icmp_echo_frame(&ep.reversed(), false, 1, self.dns_id));
        } else if roll < 89 {
            push(out, synth::arp_request_frame(DEMO_GATEWAY_MAC, DEMO_GATEWAY_IP, LAN_PEERS[0].0));
        } else if roll < 91 {
            let ep = Endpoints {
                src_mac: peer_mac(LAN_PEERS[0].1),
                dst_mac: MacAddr::BROADCAST,
                src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                dst_ip: IpAddr::V4(Ipv4Addr::BROADCAST),
            };
            push(out, synth::udp_frame(&ep, 68, 67, &[0u8; 240]));
        } else if roll < 95 {
            let ep = Self::local_to(REMOTES[4].0, DEMO_GATEWAY_MAC);
            push(out, synth::tcp_frame(&ep, 51080, 80, self.seq, 1, TcpFlags::ACK | TcpFlags::PSH, &synth::http_get(REMOTES[4].1, "/manifest.json")));
            push(out, synth::tcp_frame(&ep.reversed(), 80, 51080, 1, self.seq, TcpFlags::ACK | TcpFlags::PSH, b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n"));
        } else {
            match self.rng.below(5) {
                0 => {
                    let (ip, last) = LAN_PEERS[0];
                    let ep = Self::local_to(ip, peer_mac(last));
                    push(out, synth::tcp_frame(&ep, 52022, 22, self.seq, 1, TcpFlags::ACK | TcpFlags::PSH, &[0u8; 64]));
                    push(out, synth::tcp_frame(&ep.reversed(), 22, 52022, 1, self.seq, TcpFlags::ACK | TcpFlags::PSH, &[0u8; 96]));
                }
                1 => {
                    let (ip, last) = LAN_PEERS[3];
                    let ep = Self::local_to(ip, peer_mac(last));
                    push(out, synth::tcp_frame(&ep, 53100, 9100, self.seq, 1, TcpFlags::ACK | TcpFlags::PSH, &[0u8; 1200]));
                }
                2 => {
                    let (ip, last) = LAN_PEERS[1];
                    let ep = Endpoints {
                        src_mac: peer_mac(last),
                        dst_mac: MacAddr([0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB]),
                        src_ip: IpAddr::V4(ip),
                        dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                    };
                    push(out, synth::udp_frame(&ep, 5353, 5353, &synth::dns_query(0, "_googlecast._tcp.local", 12)));
                }
                3 => {
                    let (ip, last) = LAN_PEERS[2];
                    let ep = Endpoints {
                        src_mac: peer_mac(last),
                        dst_mac: MacAddr([0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA]),
                        src_ip: IpAddr::V4(ip),
                        dst_ip: IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
                    };
                    push(out, synth::udp_frame(&ep, 50000, 1900, b"M-SEARCH * HTTP/1.1\r\n\r\n"));
                }
                _ => self.hostile(out, &push),
            }
        }
    }

    /// Rare attack-like traffic so the threat colouring can be seen without a real attacker.
    fn hostile(&mut self, out: &mut Vec<RawFrame>, push: &impl Fn(&mut Vec<RawFrame>, Vec<u8>)) {
        match self.rng.below(3) {
            0 => {
                let (ip, last) = DEMO_SCANNER;
                let ep = Endpoints { src_mac: peer_mac(last), dst_mac: DEMO_LOCAL_MAC, src_ip: IpAddr::V4(ip), dst_ip: IpAddr::V4(DEMO_LOCAL_IP) };
                let first = 20 + self.rng.below(1000) as u16;
                for port in first..first + SCAN_BURST {
                    push(out, synth::tcp_frame(&ep, 61000, port, self.seq, 0, TcpFlags::SYN, b""));
                }
            }
            1 => {
                let ep = Self::local_to(DEMO_C2, DEMO_GATEWAY_MAC);
                push(out, synth::tcp_frame(&ep, 50444, 4444, self.seq, 1, TcpFlags::ACK | TcpFlags::PSH, &[0u8; 180]));
                push(out, synth::tcp_frame(&ep.reversed(), 4444, 50444, 1, self.seq, TcpFlags::ACK | TcpFlags::PSH, &[0u8; 620]));
            }
            _ => {
                let ep = Self::local_to(DEMO_C2, DEMO_GATEWAY_MAC).reversed();
                push(out, synth::tcp_frame(&ep, 61001, 80 + self.rng.below(400) as u16, self.seq, 0, TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG, b""));
            }
        }
    }
}

/// Target packet rate with slow sinusoidal swell so density changes are visible.
fn target_rate(base_pps: f64, elapsed: Duration) -> f64 {
    const SWELL_PERIOD_SECS: f64 = 20.0;
    const SWELL_DEPTH: f64 = 0.7;
    let phase = elapsed.as_secs_f64() / SWELL_PERIOD_SECS * std::f64::consts::TAU;
    base_pps * (1.0 + SWELL_DEPTH * phase.sin()).max(0.1)
}

pub fn run_demo(tx: &FrameSender, stop: &AtomicBool, base_pps: f64, seed: u64) {
    let mut gen = DemoGenerator::new(seed);
    let start = Instant::now();
    let mut owed = 0.0f64;
    let mut buf = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        owed += target_rate(base_pps, start.elapsed()) * TICK.as_secs_f64();
        while owed >= 1.0 {
            gen.step(wall_clock_us(), &mut buf);
            owed -= buf.len() as f64;
            for frame in buf.drain(..) {
                if !tx.offer(frame) {
                    return;
                }
            }
        }
        std::thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::packet::{Direction, TrafficClass};

    #[test]
    fn demo_frames_parse_cleanly_and_cover_classes() {
        let mut gen = DemoGenerator::new(42);
        let mut engine = Engine::new(demo_engine_config());
        let mut frames = Vec::new();
        for i in 0..2000 {
            gen.step(i * 1000, &mut frames);
        }
        for f in &frames {
            engine.ingest(f);
        }
        let batch = engine.take_batch();
        assert!(batch.packets as usize == frames.len());
        let stats = engine.stats(3_000_000);
        assert_eq!(stats.malformed_packets, 0);
        for class in [TrafficClass::Https, TrafficClass::Dns, TrafficClass::Icmp, TrafficClass::Arp, TrafficClass::Dhcp, TrafficClass::Http, TrafficClass::Tcp] {
            assert!(stats.class_totals[&class] > 0, "{class:?} missing");
        }
        assert!(batch.events.iter().any(|e| e.direction == Direction::Incoming));
        assert!(batch.events.iter().any(|e| e.direction == Direction::Outgoing));
        let devices = engine.devices();
        assert!(devices.iter().any(|d| d.role == crate::devices::DeviceRole::Gateway));
        assert!(devices.iter().filter(|d| d.role == crate::devices::DeviceRole::Lan).count() >= 4);
        assert!(batch.events.iter().any(|e| e.dst_node == crate::devices::NodeRef::Internet));
        assert!(batch.events.iter().any(|e| e.dst_node == crate::devices::NodeRef::Broadcast));
        assert!(stats.threat_packets > 0, "demo shows hostile traffic");
        assert!(stats.threat_packets * 10 < stats.total_packets, "but only a little");
    }
}
