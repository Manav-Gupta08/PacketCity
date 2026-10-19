//! Per-packet threat marking. A packet is flagged when its own headers are hostile (illegal TCP
//! flag combinations, LAND packets, well-known backdoor ports) or when its sender was recently
//! caught scanning or claiming another device's address. Like the alerts, these are explainable
//! metadata heuristics, not an IDS: they paint traffic red so it stands out, nothing more.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::Serialize;

use crate::packet::{AppProtocol, ParsedPacket, TcpFlags, TransportProtocol};

const US_PER_SEC: u64 = 1_000_000;
/// A source stays flagged for this long after the last evidence against it.
pub const FLAG_TTL_US: u64 = 300 * US_PER_SEC;
const MAX_FLAGGED_SOURCES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ThreatKind {
    /// Sender was detected port-scanning or sweeping hosts.
    Scanner,
    /// NULL, FIN, XMAS, SYN+FIN or SYN+RST: flag sets no normal TCP stack sends.
    StealthScan,
    /// Source and destination address and port are identical (LAND attack).
    Land,
    /// Port associated with well-known backdoors, RATs or botnet C2.
    BackdoorPort,
    /// ARP from an address that two MACs claim (possible ARP spoofing).
    ArpSpoof,
    /// Sender keeps opening connections to a login service (SSH, RDP, …): password guessing.
    BruteForce,
    /// DNS name with a long, random-looking label: data smuggled through DNS.
    DnsTunnel,
}

/// Ports no ordinary service uses but well-known malware does. None fall in common ephemeral
/// ranges (Windows 49152+, Linux 32768–60999), so client ports do not trigger false positives.
const BACKDOOR_PORTS: [u16; 10] = [1337, 2745, 3127, 4444, 5554, 6667, 9996, 12345, 27374, 31337];
/// Ordinary hostnames rarely have labels this long; encoded payloads (base32/hex) do.
const TUNNEL_MIN_LABEL: usize = 40;
/// Bits per character; English-like or word-based labels stay well below this.
const TUNNEL_MIN_ENTROPY: f64 = 3.6;

/// True for names whose longest label is long and close to uniformly random.
pub fn looks_like_dns_tunnel(name: &str) -> bool {
    let Some(label) = name.split('.').max_by_key(|l| l.len()) else { return false };
    if label.len() < TUNNEL_MIN_LABEL {
        return false;
    }
    let mut counts = [0u32; 256];
    for b in label.bytes() {
        counts[usize::from(b.to_ascii_lowercase())] += 1;
    }
    let n = label.len() as f64;
    let entropy: f64 = counts.iter().filter(|&&c| c > 0).map(|&c| f64::from(c) / n).map(|p| -p * p.log2()).sum();
    entropy >= TUNNEL_MIN_ENTROPY
}

#[derive(Debug, Default)]
pub struct ThreatTracker {
    flagged: HashMap<IpAddr, (u64, ThreatKind)>,
}

fn stealth_flags(flags: TcpFlags) -> bool {
    let (syn, ack, fin, rst) = (flags.has(TcpFlags::SYN), flags.has(TcpFlags::ACK), flags.has(TcpFlags::FIN), flags.has(TcpFlags::RST));
    flags.0 == 0 || (fin && !ack && !rst) || (syn && fin) || (syn && rst)
}

impl ThreatTracker {
    /// Marks `ip` as hostile from `ts` for `FLAG_TTL_US`; repeated evidence extends the period.
    pub fn flag(&mut self, ip: IpAddr, kind: ThreatKind, ts: u64) {
        if !self.flagged.contains_key(&ip) && self.flagged.len() >= MAX_FLAGGED_SOURCES {
            return;
        }
        self.flagged.insert(ip, (ts, kind));
    }

    pub fn assess(&self, pkt: &ParsedPacket, ts: u64) -> Option<ThreatKind> {
        if let Some(t) = pkt.tcp.as_ref().filter(|_| pkt.transport == TransportProtocol::Tcp) {
            if stealth_flags(t.flags) {
                return Some(ThreatKind::StealthScan);
            }
        }
        // LAND only makes sense for TCP/UDP, which always carry ports; ARP's sender/target IPs
        // legitimately match for a gratuitous announcement, which is not an attack.
        if let (Some(sp), Some(dp)) = (pkt.src_port(), pkt.dst_port()) {
            let (src, dst) = (pkt.src_ip(), pkt.dst_ip());
            if src.is_some() && src == dst && sp == dp && !src.is_some_and(|s| s.is_loopback() || s.is_unspecified()) {
                return Some(ThreatKind::Land);
            }
        }
        if [pkt.src_port(), pkt.dst_port()].into_iter().flatten().any(|p| BACKDOOR_PORTS.contains(&p)) {
            return Some(ThreatKind::BackdoorPort);
        }
        if let Some(name) = pkt.dns.as_ref().filter(|_| pkt.app == AppProtocol::Dns).and_then(|d| d.query_name.as_deref()) {
            if looks_like_dns_tunnel(name) {
                return Some(ThreatKind::DnsTunnel);
            }
        }
        let (since, kind) = *self.flagged.get(&pkt.src_ip()?)?;
        let applies = kind != ThreatKind::ArpSpoof || pkt.arp.is_some();
        (applies && ts.saturating_sub(since) <= FLAG_TTL_US).then_some(kind)
    }

    pub fn maintain(&mut self, now_us: u64) {
        self.flagged.retain(|_, (since, _)| now_us.saturating_sub(*since) <= FLAG_TTL_US);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::frame::LinkType;
    use crate::packet::MacAddr;
    use crate::parser::parse_frame;
    use crate::synth::{self, Endpoints};

    fn ep(src: Ipv4Addr, dst: Ipv4Addr) -> Endpoints {
        Endpoints { src_mac: MacAddr([2, 0, 0, 0, 0, 1]), dst_mac: MacAddr([2, 0, 0, 0, 0, 2]), src_ip: IpAddr::V4(src), dst_ip: IpAddr::V4(dst) }
    }

    fn tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> ParsedPacket {
        let f = synth::tcp_frame(&ep(src, dst), sport, dport, 1, 0, flags, b"");
        parse_frame(LinkType::Ethernet, &f, f.len() as u32)
    }

    const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);

    #[test]
    fn normal_handshake_is_clean() {
        let t = ThreatTracker::default();
        for flags in [TcpFlags::SYN, TcpFlags::SYN | TcpFlags::ACK, TcpFlags::ACK, TcpFlags::FIN | TcpFlags::ACK, TcpFlags::RST, TcpFlags::RST | TcpFlags::ACK] {
            assert_eq!(t.assess(&tcp(A, B, 50000, 443, flags), 0), None, "flags {flags:#x}");
        }
    }

    #[test]
    fn stealth_scan_flag_sets() {
        let t = ThreatTracker::default();
        for flags in [0, TcpFlags::FIN, TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG, TcpFlags::SYN | TcpFlags::FIN, TcpFlags::SYN | TcpFlags::RST] {
            assert_eq!(t.assess(&tcp(A, B, 50000, 80, flags), 0), Some(ThreatKind::StealthScan), "flags {flags:#x}");
        }
    }

    #[test]
    fn land_and_backdoor_ports() {
        let t = ThreatTracker::default();
        assert_eq!(t.assess(&tcp(A, A, 139, 139, TcpFlags::SYN), 0), Some(ThreatKind::Land));
        assert_eq!(t.assess(&tcp(A, B, 50000, 4444, TcpFlags::SYN), 0), Some(ThreatKind::BackdoorPort));
        assert_eq!(t.assess(&tcp(B, A, 31337, 50000, TcpFlags::ACK), 0), Some(ThreatKind::BackdoorPort));
    }

    #[test]
    fn dns_tunnel_names() {
        assert!(looks_like_dns_tunnel("mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpjqwe3dfnz2a.t.evil.example"));
        assert!(looks_like_dns_tunnel("4a7f1c9e0b3d62f85e1a9c7b4d0e2f6a8c1b3e5d7f9a0c2e.cdn.example"));
        for ok in ["www.google.com", "internal-api-prod-1234567890.us-east-1.elb.amazonaws.com", "_googlecast._tcp.local", ""] {
            assert!(!looks_like_dns_tunnel(ok), "{ok}");
        }
        assert!(!looks_like_dns_tunnel(&"a".repeat(60)), "long but not random");
    }

    #[test]
    fn flagged_sources_expire() {
        let mut t = ThreatTracker::default();
        t.flag(IpAddr::V4(B), ThreatKind::Scanner, 1_000);
        let pkt = tcp(B, A, 50000, 443, TcpFlags::ACK);
        assert_eq!(t.assess(&pkt, 2_000), Some(ThreatKind::Scanner));
        assert_eq!(t.assess(&tcp(A, B, 50000, 443, TcpFlags::ACK), 2_000), None, "only the sender is flagged");
        assert_eq!(t.assess(&pkt, 1_000 + FLAG_TTL_US + 1), None);
        t.maintain(1_000 + FLAG_TTL_US + 1);
        assert!(t.flagged.is_empty());
    }

    #[test]
    fn spoofed_address_flags_only_arp() {
        let mut t = ThreatTracker::default();
        t.flag(IpAddr::V4(B), ThreatKind::ArpSpoof, 0);
        assert_eq!(t.assess(&tcp(B, A, 50000, 443, TcpFlags::ACK), 1), None);
        let f = synth::arp_request_frame(MacAddr([2, 0, 0, 0, 0, 9]), B, A);
        assert_eq!(t.assess(&parse_frame(LinkType::Ethernet, &f, f.len() as u32), 1), Some(ThreatKind::ArpSpoof));
    }
}
