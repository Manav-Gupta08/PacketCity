use super::bytes::{be16, sanitize_hostname};
use crate::packet::TlsInfo;

const RECORD_HEADER_LEN: usize = 5;
/// RFC 8446 §5.1: records must not exceed 2^14 bytes plus expansion allowance.
const MAX_RECORD_LEN: u16 = 16384 + 2048;
const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_HEADER_LEN: usize = 4;
const CLIENT_RANDOM_LEN: usize = 32;
const EXT_SERVER_NAME: u16 = 0;
const SNI_HOST_NAME: u8 = 0;

/// Recognises a TLS record header and, for ClientHello, extracts SNI.
pub(super) fn parse(b: &[u8]) -> Option<TlsInfo> {
    if b.len() < RECORD_HEADER_LEN {
        return None;
    }
    let content_type = b[0];
    let content_type_name = content_type_name(content_type)?;
    let record_version = be16(b, 1)?;
    let record_len = be16(b, 3)?;
    // Major version 3 covers SSL 3.0 through TLS 1.3 (which still uses 0x0303 on the wire).
    if record_version >> 8 != 3 || record_version & 0xFF > 4 || record_len == 0 || record_len > MAX_RECORD_LEN {
        return None;
    }

    let handshake_type = (content_type == CONTENT_HANDSHAKE).then(|| b.get(RECORD_HEADER_LEN).copied()).flatten();
    let sni = if handshake_type == Some(HANDSHAKE_CLIENT_HELLO) {
        b.get(RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN..).and_then(client_hello_sni)
    } else {
        None
    };

    Some(TlsInfo { content_type, content_type_name, record_version, handshake_type, sni })
}

/// Full record length when `payload` starts a ClientHello record it does not completely contain.
pub(crate) fn incomplete_client_hello_len(payload: &[u8]) -> Option<usize> {
    let info = parse(payload)?;
    if info.handshake_type != Some(HANDSHAKE_CLIENT_HELLO) || info.sni.is_some() {
        return None;
    }
    let total = RECORD_HEADER_LEN + usize::from(be16(payload, 3)?);
    (payload.len() < total).then_some(total)
}

/// SNI of a reassembled ClientHello record.
pub(crate) fn record_sni(record: &[u8]) -> Option<String> {
    parse(record)?.sni
}

fn content_type_name(t: u8) -> Option<&'static str> {
    match t {
        20 => Some("ChangeCipherSpec"),
        21 => Some("Alert"),
        22 => Some("Handshake"),
        23 => Some("ApplicationData"),
        24 => Some("Heartbeat"),
        _ => None,
    }
}

/// Walks a ClientHello body. Returns `None` on truncation — the SNI may live in a later segment.
fn client_hello_sni(b: &[u8]) -> Option<String> {
    let mut pos = 2 + CLIENT_RANDOM_LEN;
    pos += 1 + usize::from(*b.get(pos)?);
    pos += 2 + usize::from(be16(b, pos)?);
    pos += 1 + usize::from(*b.get(pos)?);
    let ext_total = usize::from(be16(b, pos)?);
    pos += 2;
    let ext_end = (pos + ext_total).min(b.len());

    while pos + 4 <= ext_end {
        let ext_type = be16(b, pos)?;
        let ext_len = usize::from(be16(b, pos + 2)?);
        let body = pos + 4;
        if ext_type == EXT_SERVER_NAME {
            // server_name_list length (2) + name_type (1) + host_name length (2)
            if *b.get(body + 2)? != SNI_HOST_NAME {
                return None;
            }
            let name_len = usize::from(be16(b, body + 3)?);
            let name = b.get(body + 5..body + 5 + name_len)?;
            return Some(sanitize_hostname(name));
        }
        pos = body + ext_len;
    }
    None
}
