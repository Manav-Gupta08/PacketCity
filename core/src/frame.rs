use serde::Serialize;

/// Link-layer framing of captured bytes. Values follow the tcpdump.org LINKTYPE registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LinkType {
    Ethernet,
    /// BSD loopback: 4-byte address family in *host* byte order (Npcap loopback adapter uses this).
    Null,
    /// OpenBSD loopback: 4-byte address family in network byte order.
    Loop,
    /// Raw IPv4/IPv6 packet with no link header.
    RawIp,
    /// Linux "cooked" capture v1 (used by the Linux `any` pseudo-interface).
    LinuxSll,
}

impl LinkType {
    pub fn from_dlt(dlt: i32) -> Option<Self> {
        match dlt {
            0 => Some(Self::Null),
            1 => Some(Self::Ethernet),
            // DLT_RAW is 12 on most platforms, 14 on OpenBSD; LINKTYPE_RAW is 101; 228/229 are IPv4/IPv6-only raw.
            12 | 14 | 101 | 228 | 229 => Some(Self::RawIp),
            108 => Some(Self::Loop),
            113 => Some(Self::LinuxSll),
            _ => None,
        }
    }
}

/// One captured frame as delivered by any capture source (live, PCAP replay, demo).
#[derive(Debug, Clone)]
pub struct RawFrame {
    /// Capture timestamp, microseconds since the Unix epoch.
    pub timestamp_us: u64,
    /// Original length on the wire (may exceed `data.len()` when truncated by snaplen).
    pub wire_len: u32,
    pub data: Vec<u8>,
}
