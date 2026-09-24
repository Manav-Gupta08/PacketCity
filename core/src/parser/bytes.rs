pub(crate) fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

pub(crate) fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub(crate) fn le32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub(crate) fn mac(b: &[u8], off: usize) -> Option<crate::packet::MacAddr> {
    let s = b.get(off..off.checked_add(6)?)?;
    let mut out = [0u8; 6];
    out.copy_from_slice(s);
    Some(crate::packet::MacAddr(out))
}

/// Keep only characters valid in DNS/host names so untrusted bytes can't inject markup or control codes.
pub(crate) fn sanitize_hostname(raw: &[u8]) -> String {
    raw.iter()
        .map(|&c| match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => c as char,
            _ => '?',
        })
        .collect()
}
