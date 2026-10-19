use crate::packet::{AppProtocol, ParsedPacket, TrafficClass, TransportProtocol};

/// Maps a parsed packet to its visual category. Application identity wins over transport so a
/// DNS query is shown as DNS rather than generic UDP.
pub fn classify(pkt: &ParsedPacket) -> TrafficClass {
    if pkt.arp.is_some() || pkt.network == crate::packet::NetworkProtocol::Arp {
        return TrafficClass::Arp;
    }
    match pkt.app {
        AppProtocol::Dns | AppProtocol::Mdns | AppProtocol::Llmnr => return TrafficClass::Dns,
        AppProtocol::Dhcp | AppProtocol::Dhcpv6 => return TrafficClass::Dhcp,
        AppProtocol::Tls | AppProtocol::Quic => return TrafficClass::Https,
        AppProtocol::Http => return TrafficClass::Http,
        _ => {}
    }
    match pkt.transport {
        TransportProtocol::Tcp => TrafficClass::Tcp,
        TransportProtocol::Udp => TrafficClass::Udp,
        TransportProtocol::Icmp | TransportProtocol::Icmpv6 => TrafficClass::Icmp,
        _ => TrafficClass::Other,
    }
}
