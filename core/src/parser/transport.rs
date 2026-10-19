use super::bytes::{be16, be32};
use super::ip::Segment;
use super::{fail, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::packet::{IcmpInfo, Layer, ParsedPacket, TcpFlags, TcpInfo, TransportProtocol, UdpInfo};

const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ICMP_MIN_HEADER_LEN: usize = 4;

/// Parses the transport header and returns the captured payload (for application detection).
pub(super) fn parse<'a>(seg: Segment<'a>, pkt: &mut ParsedPacket) -> Option<&'a [u8]> {
    match seg.protocol {
        IPPROTO_TCP => tcp(seg, pkt),
        IPPROTO_UDP => udp(seg, pkt),
        IPPROTO_ICMP => {
            icmp(seg.bytes, 4, pkt);
            None
        }
        IPPROTO_ICMPV6 => {
            icmp(seg.bytes, 6, pkt);
            None
        }
        _ => {
            pkt.transport = TransportProtocol::Unknown;
            None
        }
    }
}

fn tcp<'a>(seg: Segment<'a>, pkt: &mut ParsedPacket) -> Option<&'a [u8]> {
    pkt.transport = TransportProtocol::Tcp;
    let b = seg.bytes;
    if b.len() < TCP_MIN_HEADER_LEN {
        fail(pkt, Layer::Transport, "truncated TCP header");
        return None;
    }
    let header_len = usize::from(b[12] >> 4) * 4;
    if header_len < TCP_MIN_HEADER_LEN || header_len > b.len() {
        fail(pkt, Layer::Transport, "invalid TCP data offset");
        return None;
    }
    pkt.tcp = Some(TcpInfo {
        src_port: be16(b, 0)?,
        dst_port: be16(b, 2)?,
        seq: be32(b, 4)?,
        ack: be32(b, 8)?,
        flags: TcpFlags(b[13]),
        window: be16(b, 14)?,
        header_len: header_len as u16,
        payload_len: seg.declared_len.saturating_sub(header_len) as u32,
    });
    Some(&b[header_len..])
}

fn udp<'a>(seg: Segment<'a>, pkt: &mut ParsedPacket) -> Option<&'a [u8]> {
    pkt.transport = TransportProtocol::Udp;
    let b = seg.bytes;
    if b.len() < UDP_HEADER_LEN {
        fail(pkt, Layer::Transport, "truncated UDP header");
        return None;
    }
    let length = be16(b, 4)?;
    let declared = if usize::from(length) >= UDP_HEADER_LEN { usize::from(length) } else { seg.declared_len };
    pkt.udp = Some(UdpInfo {
        src_port: be16(b, 0)?,
        dst_port: be16(b, 2)?,
        length,
        payload_len: declared.saturating_sub(UDP_HEADER_LEN) as u32,
    });
    let end = declared.min(b.len()).max(UDP_HEADER_LEN);
    Some(&b[UDP_HEADER_LEN..end])
}

fn icmp(b: &[u8], version: u8, pkt: &mut ParsedPacket) {
    pkt.transport = if version == 4 { TransportProtocol::Icmp } else { TransportProtocol::Icmpv6 };
    if b.len() < ICMP_MIN_HEADER_LEN {
        fail(pkt, Layer::Transport, "truncated ICMP header");
        return;
    }
    let (icmp_type, code) = (b[0], b[1]);
    let description = if version == 4 { icmpv4_name(icmp_type) } else { icmpv6_name(icmp_type) };
    pkt.icmp = Some(IcmpInfo { version, icmp_type, code, description });
}

fn icmpv4_name(t: u8) -> &'static str {
    match t {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        5 => "Redirect",
        8 => "Echo Request",
        9 => "Router Advertisement",
        10 => "Router Solicitation",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp",
        14 => "Timestamp Reply",
        _ => "Other",
    }
}

fn icmpv6_name(t: u8) -> &'static str {
    match t {
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        4 => "Parameter Problem",
        128 => "Echo Request",
        129 => "Echo Reply",
        130..=132 | 143 => "Multicast Listener",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        137 => "Redirect",
        _ => "Other",
    }
}
