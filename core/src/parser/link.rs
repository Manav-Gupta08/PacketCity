use super::bytes::{be16, le32, mac};
use super::{fail, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use crate::frame::LinkType;
use crate::packet::{EthernetInfo, Layer, ParsedPacket};

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
const MAX_VLAN_TAGS: usize = 2;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ETHERTYPE_QINQ_LEGACY: u16 = 0x9100;
/// EtherType values below this are IEEE 802.3 length fields, not protocol identifiers.
const ETHERTYPE_MIN: u16 = 0x0600;
const NULL_HEADER_LEN: usize = 4;
const SLL_HEADER_LEN: usize = 16;

/// Network-layer bytes plus the EtherType-equivalent identifying them.
pub(super) struct NetLayer<'a> {
    pub ether_type: u16,
    pub bytes: &'a [u8],
}

pub(super) fn parse<'a>(link: LinkType, data: &'a [u8], pkt: &mut ParsedPacket) -> Option<NetLayer<'a>> {
    match link {
        LinkType::Ethernet => ethernet(data, pkt),
        LinkType::Null => null_loopback(data, pkt, false),
        LinkType::Loop => null_loopback(data, pkt, true),
        LinkType::RawIp => raw_ip(data, pkt),
        LinkType::LinuxSll => linux_sll(data, pkt),
    }
}

fn ethernet<'a>(data: &'a [u8], pkt: &mut ParsedPacket) -> Option<NetLayer<'a>> {
    if data.len() < ETHERNET_HEADER_LEN {
        fail(pkt, Layer::Link, "truncated Ethernet header");
        return None;
    }
    let dst = mac(data, 0)?;
    let src = mac(data, 6)?;
    let mut ether_type = be16(data, 12)?;
    let mut offset = ETHERNET_HEADER_LEN;
    let mut vlan = None;

    for _ in 0..MAX_VLAN_TAGS {
        if !matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_LEGACY) {
            break;
        }
        let (Some(tci), Some(inner)) = (be16(data, offset), be16(data, offset + 2)) else {
            fail(pkt, Layer::Link, "truncated VLAN tag");
            return None;
        };
        vlan.get_or_insert(tci & 0x0FFF);
        ether_type = inner;
        offset += VLAN_TAG_LEN;
    }

    pkt.ethernet = Some(EthernetInfo { src, dst, ether_type, vlan });
    if ether_type < ETHERTYPE_MIN {
        return None;
    }
    Some(NetLayer { ether_type, bytes: &data[offset..] })
}

/// Address-family values differ per OS: AF_INET is always 2, AF_INET6 is 10 (Linux),
/// 23 (Windows), 24/28/30 (BSDs/macOS).
fn family_to_ether_type(family: u32) -> Option<u16> {
    match family {
        2 => Some(ETHERTYPE_IPV4),
        10 | 23 | 24 | 28 | 30 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

fn null_loopback<'a>(data: &'a [u8], pkt: &mut ParsedPacket, network_order: bool) -> Option<NetLayer<'a>> {
    let Some(raw) = le32(data, 0) else {
        fail(pkt, Layer::Link, "truncated loopback header");
        return None;
    };
    // DLT_NULL is host byte order of the *capturing* machine, which may differ from ours (PCAP replay).
    let family = if network_order || raw > 0xFFFF { raw.swap_bytes() } else { raw };
    match family_to_ether_type(family) {
        Some(ether_type) => Some(NetLayer { ether_type, bytes: &data[NULL_HEADER_LEN..] }),
        None => {
            fail(pkt, Layer::Link, "unknown loopback address family");
            None
        }
    }
}

fn raw_ip<'a>(data: &'a [u8], pkt: &mut ParsedPacket) -> Option<NetLayer<'a>> {
    match data.first().map(|b| b >> 4) {
        Some(4) => Some(NetLayer { ether_type: ETHERTYPE_IPV4, bytes: data }),
        Some(6) => Some(NetLayer { ether_type: ETHERTYPE_IPV6, bytes: data }),
        _ => {
            fail(pkt, Layer::Link, "raw packet is not IPv4 or IPv6");
            None
        }
    }
}

fn linux_sll<'a>(data: &'a [u8], pkt: &mut ParsedPacket) -> Option<NetLayer<'a>> {
    match be16(data, 14) {
        Some(ether_type) if data.len() >= SLL_HEADER_LEN => {
            Some(NetLayer { ether_type, bytes: &data[SLL_HEADER_LEN..] })
        }
        _ => {
            fail(pkt, Layer::Link, "truncated Linux cooked header");
            None
        }
    }
}
