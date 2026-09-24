use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::bytes::{be16, be32};
use super::fail;
use crate::packet::{IpInfo, Layer, NetworkProtocol, ParsedPacket};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const MAX_IPV6_EXTENSION_HEADERS: usize = 8;

const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_ESP: u8 = 50;
const IPV6_AUTH: u8 = 51;
const IPV6_NO_NEXT: u8 = 59;
const IPV6_DEST_OPTS: u8 = 60;
const IPV6_MOBILITY: u8 = 135;

/// Transport-layer bytes (captured) and the length the IP header says they should have.
pub(super) struct Segment<'a> {
    pub protocol: u8,
    pub bytes: &'a [u8],
    pub declared_len: usize,
}

pub(super) fn parse_ipv4<'a>(b: &'a [u8], pkt: &mut ParsedPacket) -> Option<Segment<'a>> {
    pkt.network = NetworkProtocol::Ipv4;
    if b.len() < IPV4_MIN_HEADER_LEN {
        fail(pkt, Layer::Network, "truncated IPv4 header");
        return None;
    }
    if b[0] >> 4 != 4 {
        fail(pkt, Layer::Network, "IPv4 version field mismatch");
        return None;
    }
    let header_len = usize::from(b[0] & 0x0F) * 4;
    if header_len < IPV4_MIN_HEADER_LEN || header_len > b.len() {
        fail(pkt, Layer::Network, "invalid IPv4 header length");
        return None;
    }
    let total_len = be16(b, 2)?;
    let flags_frag = be16(b, 6)?;
    // total_len == 0 happens with TCP segmentation offload on the sending host; fall back to captured size.
    let effective_total = if total_len == 0 { b.len() } else { usize::from(total_len) };
    if effective_total < header_len {
        fail(pkt, Layer::Network, "IPv4 total length smaller than header");
        return None;
    }

    let info = IpInfo {
        version: 4,
        src: IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
        dst: IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
        ttl: b[8],
        protocol: b[9],
        header_len: header_len as u16,
        total_len,
        dscp: b[1] >> 2,
        ecn: b[1] & 0x03,
        identification: be16(b, 4),
        dont_fragment: flags_frag & 0x4000 != 0,
        more_fragments: flags_frag & 0x2000 != 0,
        fragment_offset: flags_frag & 0x1FFF,
        flow_label: None,
    };
    let non_first_fragment = info.is_non_first_fragment();
    let protocol = info.protocol;
    pkt.ip = Some(info);

    if non_first_fragment {
        return None;
    }
    let end = effective_total.min(b.len());
    Some(Segment { protocol, bytes: &b[header_len..end], declared_len: effective_total - header_len })
}

pub(super) fn parse_ipv6<'a>(b: &'a [u8], pkt: &mut ParsedPacket) -> Option<Segment<'a>> {
    pkt.network = NetworkProtocol::Ipv6;
    if b.len() < IPV6_HEADER_LEN {
        fail(pkt, Layer::Network, "truncated IPv6 header");
        return None;
    }
    if b[0] >> 4 != 6 {
        fail(pkt, Layer::Network, "IPv6 version field mismatch");
        return None;
    }
    let vtf = be32(b, 0)?;
    let payload_len = usize::from(be16(b, 4)?);
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&b[8..24]);
    dst.copy_from_slice(&b[24..40]);

    let mut next = b[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut fragment_offset = 0u16;
    let mut more_fragments = false;
    let mut walked = 0;

    while is_extension_header(next) {
        walked += 1;
        if walked > MAX_IPV6_EXTENSION_HEADERS {
            fail(pkt, Layer::Network, "too many IPv6 extension headers");
            break;
        }
        let (Some(&following), Some(&len_field)) = (b.get(offset), b.get(offset + 1)) else {
            fail(pkt, Layer::Network, "truncated IPv6 extension header");
            break;
        };
        let ext_len = match next {
            IPV6_FRAGMENT => {
                let frag = be16(b, offset + 2).unwrap_or(0);
                fragment_offset = frag >> 3;
                more_fragments = frag & 0x1 != 0;
                8
            }
            IPV6_AUTH => (usize::from(len_field) + 2) * 4,
            _ => (usize::from(len_field) + 1) * 8,
        };
        next = following;
        offset += ext_len;
    }

    let info = IpInfo {
        version: 6,
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        ttl: b[7],
        protocol: next,
        header_len: offset.min(usize::from(u16::MAX)) as u16,
        total_len: (IPV6_HEADER_LEN + payload_len).min(usize::from(u16::MAX)) as u16,
        dscp: ((vtf >> 22) & 0x3F) as u8,
        ecn: ((vtf >> 20) & 0x03) as u8,
        identification: None,
        dont_fragment: false,
        more_fragments,
        fragment_offset,
        flow_label: Some(vtf & 0x000F_FFFF),
    };
    pkt.ip = Some(info);

    if pkt.issue.is_some() || fragment_offset != 0 || next == IPV6_ESP || next == IPV6_NO_NEXT {
        return None;
    }
    let declared_end = IPV6_HEADER_LEN + payload_len;
    if offset > b.len() || offset > declared_end {
        fail(pkt, Layer::Network, "IPv6 extension headers exceed packet");
        return None;
    }
    let end = declared_end.min(b.len());
    Some(Segment { protocol: next, bytes: &b[offset..end], declared_len: declared_end - offset })
}

fn is_extension_header(next: u8) -> bool {
    matches!(
        next,
        IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_FRAGMENT | IPV6_AUTH | IPV6_DEST_OPTS | IPV6_MOBILITY
    )
}
