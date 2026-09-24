//! Direction relative to the capturing host.
//!
//! The capture interface's own IP addresses (reported by libpcap/Npcap) define "this host".
//! A packet is Outgoing if its source is local, Incoming if its destination is local or it is
//! broadcast/multicast that this interface received, Local if both ends are local, and Transit
//! otherwise (e.g. traffic from a SPAN/mirror port). MAC addresses are used as a fallback for
//! frames without IP information.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::packet::{Cast, Direction, MacAddr, ParsedPacket};

#[derive(Clone, Debug, Default)]
pub struct LocalHost {
    ips: HashSet<IpAddr>,
    broadcast_ips: HashSet<IpAddr>,
    macs: HashSet<MacAddr>,
}

impl LocalHost {
    pub fn new(ips: impl IntoIterator<Item = IpAddr>, broadcast_ips: impl IntoIterator<Item = IpAddr>) -> Self {
        Self { ips: ips.into_iter().collect(), broadcast_ips: broadcast_ips.into_iter().collect(), macs: HashSet::new() }
    }

    pub fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip) || ip.is_loopback()
    }

    pub fn ips(&self) -> impl Iterator<Item = &IpAddr> {
        self.ips.iter()
    }

    pub fn is_local_mac(&self, mac: &MacAddr) -> bool {
        self.macs.contains(mac)
    }

    /// Our MAC is not reported by libpcap on every platform, so it is learned from frames whose
    /// source IP is ours. This makes non-IP frames (e.g. ARP replies) directionally correct.
    fn learn_mac(&mut self, pkt: &ParsedPacket) {
        if let (Some(eth), Some(src)) = (&pkt.ethernet, pkt.src_ip()) {
            if self.ips.contains(&src) && !eth.src.is_multicast() && !eth.src.is_broadcast() {
                self.macs.insert(eth.src);
            }
        }
    }

    pub fn cast(&self, pkt: &ParsedPacket) -> Cast {
        if let Some(dst) = pkt.ip.as_ref().map(|ip| ip.dst) {
            if dst.is_multicast() {
                return Cast::Multicast;
            }
            if self.broadcast_ips.contains(&dst) || matches!(dst, IpAddr::V4(v4) if v4.is_broadcast()) {
                return Cast::Broadcast;
            }
        }
        match pkt.ethernet.as_ref().map(|e| e.dst) {
            Some(mac) if mac.is_broadcast() => Cast::Broadcast,
            Some(mac) if mac.is_multicast() => Cast::Multicast,
            _ => Cast::Unicast,
        }
    }

    pub fn direction(&mut self, pkt: &ParsedPacket, cast: Cast) -> Direction {
        self.learn_mac(pkt);
        let src_local = pkt.src_ip().map(|ip| self.is_local_ip(&ip)).or_else(|| self.mac_is_local(pkt, true));
        let dst_local = pkt.dst_ip().map(|ip| self.is_local_ip(&ip)).or_else(|| self.mac_is_local(pkt, false));
        match (src_local.unwrap_or(false), dst_local.unwrap_or(false)) {
            (true, true) => Direction::Local,
            (true, false) => Direction::Outgoing,
            (false, true) => Direction::Incoming,
            (false, false) if cast != Cast::Unicast => Direction::Incoming,
            (false, false) => Direction::Transit,
        }
    }

    fn mac_is_local(&self, pkt: &ParsedPacket, source: bool) -> Option<bool> {
        let eth = pkt.ethernet.as_ref()?;
        Some(self.macs.contains(if source { &eth.src } else { &eth.dst }))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::frame::LinkType;
    use crate::parser::parse_frame;
    use crate::synth::{self, Endpoints};

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
    const MY_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 0x20]);
    const ROUTER_MAC: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);

    fn host() -> LocalHost {
        LocalHost::new([IpAddr::V4(ME)], [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))])
    }

    fn ep(src: Ipv4Addr, dst: Ipv4Addr) -> Endpoints {
        Endpoints { src_mac: MY_MAC, dst_mac: ROUTER_MAC, src_ip: IpAddr::V4(src), dst_ip: IpAddr::V4(dst) }
    }

    fn dir(h: &mut LocalHost, frame: &[u8]) -> (Direction, Cast) {
        let pkt = parse_frame(LinkType::Ethernet, frame, frame.len() as u32);
        let cast = h.cast(&pkt);
        (h.direction(&pkt, cast), cast)
    }

    #[test]
    fn outgoing_incoming_transit_local() {
        let mut h = host();
        let remote = Ipv4Addr::new(8, 8, 8, 8);
        let other = Ipv4Addr::new(192, 168, 1, 50);
        assert_eq!(dir(&mut h, &synth::udp_frame(&ep(ME, remote), 1, 53, b"")).0, Direction::Outgoing);
        assert_eq!(dir(&mut h, &synth::udp_frame(&ep(remote, ME), 53, 1, b"")).0, Direction::Incoming);
        assert_eq!(dir(&mut h, &synth::udp_frame(&ep(other, remote), 1, 2, b"")).0, Direction::Transit);
        assert_eq!(dir(&mut h, &synth::udp_frame(&ep(ME, ME), 1, 2, b"")).0, Direction::Local);
    }

    #[test]
    fn broadcast_from_others_is_incoming() {
        let mut h = host();
        let frame = synth::udp_frame(&ep(Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 1, 255)), 137, 137, b"");
        assert_eq!(dir(&mut h, &frame), (Direction::Incoming, Cast::Broadcast));
        let mdns = synth::udp_frame(&ep(Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(224, 0, 0, 251)), 5353, 5353, b"");
        assert_eq!(dir(&mut h, &mdns), (Direction::Incoming, Cast::Multicast));
    }

    #[test]
    fn arp_uses_protocol_addresses() {
        let mut h = host();
        let ours = synth::arp_request_frame(MY_MAC, ME, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(dir(&mut h, &ours), (Direction::Outgoing, Cast::Broadcast));
        let theirs = synth::arp_request_frame(ROUTER_MAC, Ipv4Addr::new(192, 168, 1, 1), ME);
        assert_eq!(dir(&mut h, &theirs).0, Direction::Incoming);
    }
}
