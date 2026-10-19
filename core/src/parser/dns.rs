use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::bytes::{be16, sanitize_hostname};
use super::fail;
use crate::packet::{DnsAnswer, DnsInfo, Layer, ParsedPacket};

const DNS_HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 255;
const MAX_POINTER_JUMPS: usize = 16;
const POINTER_MASK: u8 = 0xC0;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// type + class + TTL + rdlength
const RR_FIXED_LEN: usize = 10;
const QUESTION_FIXED_LEN: usize = 4;
const MAX_QUESTIONS: u16 = 8;
const MAX_ANSWER_RECORDS: u16 = 64;
const MAX_ANSWER_ADDRS: usize = 16;
const RCODE_NOERROR: u8 = 0;

pub(super) fn parse(b: &[u8], pkt: &mut ParsedPacket) -> Option<DnsInfo> {
    if b.len() < DNS_HEADER_LEN {
        fail(pkt, Layer::Application, "truncated DNS header");
        return None;
    }
    let flags = be16(b, 2)?;
    let question_count = be16(b, 4)?;
    let (query_name, query_type) = if question_count > 0 {
        match read_name(b, DNS_HEADER_LEN) {
            Some((name, end)) => (Some(name), be16(b, end)),
            None => {
                fail(pkt, Layer::Application, "malformed DNS question name");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let is_response = flags & 0x8000 != 0;
    let rcode = (flags & 0x000F) as u8;
    let answer_count = be16(b, 6)?;
    let other_records = be16(b, 8)?.saturating_add(be16(b, 10)?);
    let answers =
        if is_response && rcode == RCODE_NOERROR { address_records(b, question_count, answer_count, other_records) } else { Vec::new() };

    Some(DnsInfo {
        transaction_id: be16(b, 0)?,
        is_response,
        opcode: ((flags >> 11) & 0x0F) as u8,
        rcode,
        question_count,
        answer_count,
        query_name,
        query_type,
        query_type_name: query_type.map(type_name),
        answers,
    })
}

/// A/AAAA records from every section (mDNS puts host addresses in "additional"). Best effort:
/// stops quietly at the first malformed record, because the question already classifies the packet.
fn address_records(b: &[u8], question_count: u16, answer_count: u16, other_records: u16) -> Vec<DnsAnswer> {
    let mut out = Vec::new();
    let Some(mut pos) = skip_questions(b, question_count) else { return out };
    for i in 0..answer_count.saturating_add(other_records).min(MAX_ANSWER_RECORDS) {
        let Some((name, end)) = read_name(b, pos) else { break };
        let (Some(rtype), Some(class), Some(rdlen)) = (be16(b, end), be16(b, end + 2), be16(b, end + 8)) else { break };
        let rdata = end + RR_FIXED_LEN;
        let Some(data) = b.get(rdata..rdata + usize::from(rdlen)) else { break };
        // mDNS sets the top class bit as "cache flush".
        let addr = match (rtype, class & 0x7FFF, data.len()) {
            (TYPE_A, CLASS_IN, 4) => Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            (TYPE_AAAA, CLASS_IN, 16) => <[u8; 16]>::try_from(data).ok().map(|a| IpAddr::V6(Ipv6Addr::from(a))),
            _ => None,
        };
        if let Some(address) = addr {
            out.push(DnsAnswer { name, address, additional: i >= answer_count });
            if out.len() == MAX_ANSWER_ADDRS {
                break;
            }
        }
        pos = rdata + usize::from(rdlen);
    }
    out
}

fn skip_questions(b: &[u8], count: u16) -> Option<usize> {
    if count > MAX_QUESTIONS {
        return None;
    }
    let mut pos = DNS_HEADER_LEN;
    for _ in 0..count {
        pos = read_name(b, pos)?.1 + QUESTION_FIXED_LEN;
    }
    (pos <= b.len()).then_some(pos)
}

/// Decodes a (possibly compressed) domain name. Returns the name and the offset just past it
/// in the *original* position (pointers do not advance the caller's cursor).
fn read_name(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name: Vec<u8> = Vec::new();
    let mut pos = start;
    let mut end_after_first_pointer = None;
    let mut jumps = 0;

    loop {
        let len = *b.get(pos)?;
        if len & POINTER_MASK == POINTER_MASK {
            let target = usize::from(be16(b, pos)? & 0x3FFF);
            end_after_first_pointer.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS || target >= b.len() {
                return None;
            }
            pos = target;
            continue;
        }
        if len & POINTER_MASK != 0 {
            return None;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let label = b.get(pos + 1..pos + 1 + usize::from(len))?;
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend_from_slice(label);
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        pos += 1 + usize::from(len);
    }

    let end = end_after_first_pointer.unwrap_or(pos);
    let text = if name.is_empty() { ".".to_string() } else { sanitize_hostname(&name) };
    Some((text, end))
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        _ => "OTHER",
    }
}
