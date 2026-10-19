//! DHCPv4 (RFC 2131/2132): only the fields that identify a device are kept.

use std::net::Ipv4Addr;

use super::bytes::{be32, mac, sanitize_hostname};
use crate::packet::DhcpInfo;

const FIXED_LEN: usize = 236;
const MAGIC_COOKIE: u32 = 0x6382_5363;
const HTYPE_ETHERNET: u8 = 1;
const OPT_PAD: u8 = 0;
const OPT_END: u8 = 255;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_MESSAGE_TYPE: u8 = 53;
const MAX_HOSTNAME: usize = 63;

pub(super) fn parse(b: &[u8]) -> Option<DhcpInfo> {
    if b.len() < FIXED_LEN + 4 || be32(b, FIXED_LEN)? != MAGIC_COOKIE {
        return None;
    }
    let client_mac = (b[1] == HTYPE_ETHERNET && b[2] == 6).then(|| mac(b, 28)).flatten();
    let your_ip = Some(Ipv4Addr::new(b[16], b[17], b[18], b[19])).filter(|ip| !ip.is_unspecified());
    let mut info = DhcpInfo { message_type: None, message_type_name: None, client_mac, hostname: None, requested_ip: None, your_ip };

    let mut pos = FIXED_LEN + 4;
    while let Some(&code) = b.get(pos) {
        match code {
            OPT_PAD => {
                pos += 1;
                continue;
            }
            OPT_END => break,
            _ => {}
        }
        let len = usize::from(*b.get(pos + 1)?);
        let Some(val) = b.get(pos + 2..pos + 2 + len) else { break };
        match (code, len) {
            (OPT_MESSAGE_TYPE, 1) => {
                info.message_type = Some(val[0]);
                info.message_type_name = Some(message_type_name(val[0]));
            }
            (OPT_HOSTNAME, 1..) => info.hostname = Some(sanitize_hostname(&val[..len.min(MAX_HOSTNAME)])),
            (OPT_REQUESTED_IP, 4) => info.requested_ip = Some(Ipv4Addr::new(val[0], val[1], val[2], val[3])),
            _ => {}
        }
        pos += 2 + len;
    }
    Some(info)
}

fn message_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "Other",
    }
}
