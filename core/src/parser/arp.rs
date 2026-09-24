use std::net::Ipv4Addr;

use super::bytes::{be16, mac};
use super::fail;
use crate::packet::{ArpInfo, Layer, NetworkProtocol, ParsedPacket};

const ARP_IPV4_OVER_ETHERNET_LEN: usize = 28;
const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;

pub(super) fn parse(b: &[u8], pkt: &mut ParsedPacket) {
    pkt.network = NetworkProtocol::Arp;
    if b.len() < ARP_IPV4_OVER_ETHERNET_LEN {
        fail(pkt, Layer::Arp, "truncated ARP packet");
        return;
    }
    let (htype, ptype) = (be16(b, 0), be16(b, 2));
    if htype != Some(HTYPE_ETHERNET) || ptype != Some(PTYPE_IPV4) || b[4] != 6 || b[5] != 4 {
        fail(pkt, Layer::Arp, "unsupported ARP hardware/protocol type");
        return;
    }
    let ip = |off: usize| Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3]);
    let (Some(operation), Some(sender_mac), Some(target_mac)) = (be16(b, 6), mac(b, 8), mac(b, 18)) else {
        return;
    };
    pkt.arp = Some(ArpInfo {
        operation,
        sender_mac,
        sender_ip: ip(14),
        target_mac,
        target_ip: ip(24),
    });
}
