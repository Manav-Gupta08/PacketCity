use std::fmt;
use std::net::IpAddr;

use crate::packet::{MacAddr, ParsedPacket, TransportProtocol};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetAddr {
    Ip(IpAddr),
    Mac(MacAddr),
}

impl fmt::Display for NetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetAddr::Ip(ip) => ip.fmt(f),
            NetAddr::Mac(mac) => mac.fmt(f),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub addr: NetAddr,
    /// 0 for protocols without ports.
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.addr, self.port) {
            (_, 0) => self.addr.fmt(f),
            (NetAddr::Ip(IpAddr::V6(v6)), port) => write!(f, "[{v6}]:{port}"),
            (addr, port) => write!(f, "{addr}:{port}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowProtocol {
    Tcp,
    Udp,
    Icmp,
    Arp,
    /// IP payload without a parsed transport header (other protocols, non-first fragments).
    OtherIp(u8),
    /// Non-IP link-layer protocol, keyed by EtherType.
    OtherLink(u16),
}

impl FlowProtocol {
    pub fn label(&self) -> String {
        match self {
            Self::Tcp => "TCP".into(),
            Self::Udp => "UDP".into(),
            Self::Icmp => "ICMP".into(),
            Self::Arp => "ARP".into(),
            Self::OtherIp(p) => format!("IP proto {p}"),
            Self::OtherLink(e) => format!("EtherType 0x{e:04x}"),
        }
    }
}

/// Direction-independent flow identity: endpoints are stored in sorted order so A→B and B→A
/// packets map to the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub lo: Endpoint,
    pub hi: Endpoint,
    pub protocol: FlowProtocol,
}

impl FlowKey {
    /// Returns the key plus the packet's (source, destination) endpoints.
    pub fn from_packet(pkt: &ParsedPacket) -> Option<(FlowKey, Endpoint, Endpoint)> {
        let (src, dst, protocol) = if let Some(ip) = &pkt.ip {
            let protocol = match (pkt.transport, pkt.tcp.is_some() || pkt.udp.is_some()) {
                (TransportProtocol::Tcp, true) => FlowProtocol::Tcp,
                (TransportProtocol::Udp, true) => FlowProtocol::Udp,
                (TransportProtocol::Icmp | TransportProtocol::Icmpv6, _) => FlowProtocol::Icmp,
                _ => FlowProtocol::OtherIp(ip.protocol),
            };
            let (sp, dp) = (pkt.src_port().unwrap_or(0), pkt.dst_port().unwrap_or(0));
            (Endpoint { addr: NetAddr::Ip(ip.src), port: sp }, Endpoint { addr: NetAddr::Ip(ip.dst), port: dp }, protocol)
        } else if let Some(arp) = &pkt.arp {
            (
                Endpoint { addr: NetAddr::Ip(IpAddr::V4(arp.sender_ip)), port: 0 },
                Endpoint { addr: NetAddr::Ip(IpAddr::V4(arp.target_ip)), port: 0 },
                FlowProtocol::Arp,
            )
        } else {
            let eth = pkt.ethernet.as_ref()?;
            (
                Endpoint { addr: NetAddr::Mac(eth.src), port: 0 },
                Endpoint { addr: NetAddr::Mac(eth.dst), port: 0 },
                FlowProtocol::OtherLink(eth.ether_type),
            )
        };
        let (lo, hi) = if src <= dst { (src, dst) } else { (dst, src) };
        Some((FlowKey { lo, hi, protocol }, src, dst))
    }
}
