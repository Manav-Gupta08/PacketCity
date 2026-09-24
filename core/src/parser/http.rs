use super::bytes::sanitize_hostname;
use crate::packet::HttpInfo;

const METHODS: [&str; 9] = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
const MAX_SCAN: usize = 2048;
const MAX_PATH_CHARS: usize = 128;

/// Parses an HTTP/1.x request or status line and the Host header.
/// Query strings are dropped: they frequently carry tokens and are payload, not metadata.
pub(super) fn parse(b: &[u8]) -> Option<HttpInfo> {
    let text = &b[..b.len().min(MAX_SCAN)];
    let mut lines = text.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let first = std::str::from_utf8(lines.next()?).ok()?;
    let mut parts = first.splitn(3, ' ');
    let (a, b2, c) = (parts.next()?, parts.next()?, parts.next().unwrap_or(""));

    let mut info = if METHODS.contains(&a) && c.starts_with("HTTP/1.") {
        let path: String = b2.split('?').next().unwrap_or("").chars().take(MAX_PATH_CHARS).collect();
        HttpInfo { method: Some(a.to_string()), path: Some(path), host: None, status: None, version: Some(c.to_string()) }
    } else if a.starts_with("HTTP/1.") && b2.len() == 3 {
        HttpInfo { method: None, path: None, host: None, status: b2.parse().ok(), version: Some(a.to_string()) }
    } else {
        return None;
    };

    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            let value = line[5..].trim_ascii();
            let host = value.split(|&c| c == b':').next().unwrap_or(value);
            info.host = Some(sanitize_hostname(host));
            break;
        }
    }
    Some(info)
}
