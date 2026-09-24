//! Zero-copy, panic-free header parsers. Every function tolerates truncated or hostile input:
//! it records the first `ParseIssue` and keeps whatever outer layers were decoded.

mod app;
mod arp;
mod bytes;
mod classify;
mod dhcp;
mod dns;
mod http;
mod ip;
mod link;
mod netbios;
mod tls;
mod transport;

pub use classify::classify;
pub(crate) use tls::{incomplete_client_hello_len, record_sni};

use crate::frame::LinkType;
use crate::packet::{Layer, ParseIssue, ParsedPacket};

pub(crate) const ETHERTYPE_IPV4: u16 = 0x0800;
pub(crate) const ETHERTYPE_ARP: u16 = 0x0806;
pub(crate) const ETHERTYPE_IPV6: u16 = 0x86DD;

pub(crate) const IPPROTO_ICMP: u8 = 1;
pub(crate) const IPPROTO_TCP: u8 = 6;
pub(crate) const IPPROTO_UDP: u8 = 17;
pub(crate) const IPPROTO_ICMPV6: u8 = 58;

/// Parse one captured frame. Never panics; malformed input yields a partially filled packet.
pub fn parse_frame(link: LinkType, data: &[u8], wire_len: u32) -> ParsedPacket {
    parse_frame_with_payload(link, data, wire_len).0
}

/// Like [`parse_frame`], also returning the captured transport payload (empty if none).
/// The payload is borrowed from `data`; callers must not retain it.
pub fn parse_frame_with_payload(link: LinkType, data: &[u8], wire_len: u32) -> (ParsedPacket, &[u8]) {
    let mut pkt = ParsedPacket::empty(data.len() as u32, wire_len);

    let Some(net) = link::parse(link, data, &mut pkt) else {
        return (pkt, &[]);
    };

    let l4 = match net.ether_type {
        ETHERTYPE_IPV4 => ip::parse_ipv4(net.bytes, &mut pkt),
        ETHERTYPE_IPV6 => ip::parse_ipv6(net.bytes, &mut pkt),
        ETHERTYPE_ARP => {
            arp::parse(net.bytes, &mut pkt);
            None
        }
        _ => None,
    };

    let mut payload: &[u8] = &[];
    if let Some(segment) = l4 {
        if let Some(p) = transport::parse(segment, &mut pkt) {
            app::detect(p, &mut pkt);
            payload = p;
        }
    }
    (pkt, payload)
}

pub(crate) fn fail(pkt: &mut ParsedPacket, layer: Layer, reason: &'static str) {
    if pkt.issue.is_none() {
        pkt.issue = Some(ParseIssue { layer, reason });
    }
}

#[cfg(test)]
mod tests;
