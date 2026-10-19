//! NetBIOS Name Service (RFC 1002), used by Windows hosts to announce their names on the LAN.

use std::net::Ipv4Addr;

use super::bytes::{be16, sanitize_hostname};
use crate::packet::NetbiosInfo;

const HEADER_LEN: usize = 12;
const ENCODED_NAME_LEN: usize = 32;
const POINTER_MASK: u8 = 0xC0;
const RR_FIXED_LEN: usize = 10;
const NB_GROUP_FLAG: u16 = 0x8000;
const TYPE_NB: u16 = 0x0020;

pub(super) fn parse(b: &[u8]) -> Option<NetbiosInfo> {
    if b.len() < HEADER_LEN {
        return None;
    }
    let flags = be16(b, 2)?;
    let (qd, an, ar) = (be16(b, 4)?, be16(b, 6)?, be16(b, 10)?);
    let mut info = NetbiosInfo {
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0F) as u8,
        opcode_name: "Other",
        rcode: (flags & 0x000F) as u8,
        name: None,
        suffix: None,
        group: false,
        address: None,
    };
    info.opcode_name = opcode_name(info.opcode);

    let mut pos = HEADER_LEN;
    if qd > 0 {
        let (name, end) = read_name(b, pos)?;
        (info.name, info.suffix) = (Some(name.0), Some(name.1));
        pos = end + 4;
    }
    // Registrations carry the address in an additional record, query responses in an answer.
    if an + ar > 0 {
        let (name, end) = match read_name(b, pos) {
            Some((n, end)) => (Some(n), end),
            None if b.get(pos).is_some_and(|c| c & POINTER_MASK == POINTER_MASK) => (None, pos + 2),
            None => return Some(info),
        };
        if let Some((n, s)) = name {
            info.name.get_or_insert(n);
            info.suffix.get_or_insert(s);
        }
        let (Some(rtype), Some(rdlen)) = (be16(b, end), be16(b, end + 8)) else { return Some(info) };
        let rdata = end + RR_FIXED_LEN;
        if rtype == TYPE_NB && rdlen >= 6 {
            if let (Some(nb_flags), Some(ip)) = (be16(b, rdata), b.get(rdata + 2..rdata + 6)) {
                info.group = nb_flags & NB_GROUP_FLAG != 0;
                info.address = Some(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
            }
        }
    }
    Some(info)
}

/// Decodes a first-level-encoded name: 16 bytes as 32 letters 'A'..'P'; last byte is the suffix.
fn read_name(b: &[u8], pos: usize) -> Option<((String, u8), usize)> {
    if usize::from(*b.get(pos)?) != ENCODED_NAME_LEN {
        return None;
    }
    let enc = b.get(pos + 1..pos + 1 + ENCODED_NAME_LEN)?;
    let mut raw = [0u8; 16];
    for (i, pair) in enc.chunks_exact(2).enumerate() {
        let (hi, lo) = (pair[0].checked_sub(b'A')?, pair[1].checked_sub(b'A')?);
        if hi > 15 || lo > 15 {
            return None;
        }
        raw[i] = hi << 4 | lo;
    }
    // Skip the (normally empty) scope labels.
    let mut end = pos + 1 + ENCODED_NAME_LEN;
    loop {
        let len = usize::from(*b.get(end)?);
        end += 1;
        if len == 0 {
            break;
        }
        end += len;
    }
    let name = sanitize_hostname(raw[..15].trim_ascii_end());
    Some(((name, raw[15]), end))
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        0 => "Query",
        5 => "Registration",
        6 => "Release",
        7 => "WACK",
        8 | 9 => "Refresh",
        _ => "Other",
    }
}
