//! Internal packet representation. Only header metadata is retained; payload bytes are never
//! stored in these types (see `docs/ARCHITECTURE.md`, "Privacy").

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Serialize, Serializer};

pub type PacketId = u64;
pub type FlowId = u64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// I/G bit of the first octet marks group (multicast) addresses.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0 && !self.is_broadcast()
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkProtocol {
    Ipv4,
    Ipv6,
    Arp,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Unknown,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AppProtocol {
    Dns,
    Mdns,
    Llmnr,
    Dhcp,
    Dhcpv6,
    Http,
    Tls,
    Quic,
    Ntp,
    Ssdp,
    Ssh,
    Nbns,
    Unknown,
}

/// Visual traffic category used by the renderer. This is a presentation grouping, not a
/// protocol hierarchy — e.g. DNS-over-UDP is `Dns`, not `Udp`. See `docs/VISUAL_MAPPING.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrafficClass {
    Tcp,
    Udp,
    Dns,
    Https,
    Http,
    Icmp,
    Arp,
    Dhcp,
    Other,
}

impl TrafficClass {
    pub const ALL: [TrafficClass; 9] = [
        Self::Tcp,
        Self::Udp,
        Self::Dns,
        Self::Https,
        Self::Http,
        Self::Icmp,
        Self::Arp,
        Self::Dhcp,
        Self::Other,
    ];

    pub fn index(self) -> usize {
        self as usize
    }
}

/// Direction relative to the capturing host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    /// Destined to this host (including broadcast/multicast it received).
    Incoming,
    /// Sent by this host.
    Outgoing,
    /// Both endpoints are this host (loopback).
    Local,
    /// Neither endpoint is this host; visible only due to broadcast domain, mirroring, etc.
    Transit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Cast {
    Unicast,
    Broadcast,
    Multicast,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;

    const NAMES: [(u8, &'static str); 8] = [
        (Self::SYN, "SYN"),
        (Self::ACK, "ACK"),
        (Self::PSH, "PSH"),
        (Self::FIN, "FIN"),
        (Self::RST, "RST"),
        (Self::URG, "URG"),
        (Self::ECE, "ECE"),
        (Self::CWR, "CWR"),
    ];

    pub fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES.into_iter().filter(move |(bit, _)| self.has(*bit)).map(|(_, n)| n)
    }
}

impl Serialize for TcpFlags {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.names())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthernetInfo {
    pub src: MacAddr,
    pub dst: MacAddr,
    pub ether_type: u16,
    /// Outermost 802.1Q VLAN ID, if tagged.
    pub vlan: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArpInfo {
    pub operation: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpInfo {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IPv4 TTL or IPv6 hop limit.
    pub ttl: u8,
    /// Upper-layer protocol number (after IPv6 extension headers).
    pub protocol: u8,
    pub header_len: u16,
    pub total_len: u16,
    pub dscp: u8,
    pub ecn: u8,
    /// IPv4 only.
    pub identification: Option<u16>,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    /// IPv6 only.
    pub flow_label: Option<u32>,
}

impl IpInfo {
    /// Only the first fragment carries the transport header.
    pub fn is_non_first_fragment(&self) -> bool {
        self.fragment_offset != 0
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub header_len: u16,
    pub payload_len: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload_len: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IcmpInfo {
    pub version: u8,
    pub icmp_type: u8,
    pub code: u8,
    pub description: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub query_name: Option<String>,
    pub query_type: Option<u16>,
    pub query_type_name: Option<&'static str>,
    /// A/AAAA records of a successful response, any section (at most 16).
    pub answers: Vec<DnsAnswer>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsAnswer {
    pub name: String,
    pub address: IpAddr,
    /// From the authority/additional sections rather than the answers.
    pub additional: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DhcpInfo {
    pub message_type: Option<u8>,
    pub message_type_name: Option<&'static str>,
    /// `chaddr` for Ethernet clients.
    pub client_mac: Option<MacAddr>,
    /// Option 12, the name the client calls itself.
    pub hostname: Option<String>,
    pub requested_ip: Option<Ipv4Addr>,
    /// Address offered/assigned by the server (`yiaddr`).
    pub your_ip: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetbiosInfo {
    pub is_response: bool,
    pub opcode: u8,
    pub opcode_name: &'static str,
    pub rcode: u8,
    pub name: Option<String>,
    /// 16th byte of the NetBIOS name: 0x00 workstation, 0x20 file server, ...
    pub suffix: Option<u8>,
    pub group: bool,
    pub address: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    pub content_type: u8,
    pub content_type_name: &'static str,
    pub record_version: u16,
    pub handshake_type: Option<u8>,
    /// Server Name Indication from a ClientHello contained in this segment.
    pub sni: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpInfo {
    pub method: Option<String>,
    pub path: Option<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub version: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Layer {
    Link,
    Arp,
    Network,
    Transport,
    Application,
}

/// First problem found while parsing. Parsing stops at the failing layer but keeps outer layers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseIssue {
    pub layer: Layer,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedPacket {
    pub captured_len: u32,
    pub wire_len: u32,
    pub network: NetworkProtocol,
    pub transport: TransportProtocol,
    pub app: AppProtocol,
    pub ethernet: Option<EthernetInfo>,
    pub arp: Option<ArpInfo>,
    pub ip: Option<IpInfo>,
    pub tcp: Option<TcpInfo>,
    pub udp: Option<UdpInfo>,
    pub icmp: Option<IcmpInfo>,
    pub dns: Option<DnsInfo>,
    pub dhcp: Option<DhcpInfo>,
    pub netbios: Option<NetbiosInfo>,
    pub tls: Option<TlsInfo>,
    pub http: Option<HttpInfo>,
    pub issue: Option<ParseIssue>,
}

impl ParsedPacket {
    pub fn empty(captured_len: u32, wire_len: u32) -> Self {
        Self {
            captured_len,
            wire_len,
            network: NetworkProtocol::Unknown,
            transport: TransportProtocol::None,
            app: AppProtocol::Unknown,
            ethernet: None,
            arp: None,
            ip: None,
            tcp: None,
            udp: None,
            icmp: None,
            dns: None,
            dhcp: None,
            netbios: None,
            tls: None,
            http: None,
            issue: None,
        }
    }

    pub fn src_ip(&self) -> Option<IpAddr> {
        self.ip.as_ref().map(|ip| ip.src).or_else(|| self.arp.as_ref().map(|a| IpAddr::V4(a.sender_ip)))
    }

    pub fn dst_ip(&self) -> Option<IpAddr> {
        self.ip.as_ref().map(|ip| ip.dst).or_else(|| self.arp.as_ref().map(|a| IpAddr::V4(a.target_ip)))
    }

    pub fn src_port(&self) -> Option<u16> {
        self.tcp.as_ref().map(|t| t.src_port).or_else(|| self.udp.as_ref().map(|u| u.src_port))
    }

    pub fn dst_port(&self) -> Option<u16> {
        self.tcp.as_ref().map(|t| t.dst_port).or_else(|| self.udp.as_ref().map(|u| u.dst_port))
    }

    /// Best-known hostname carried by this packet (TLS SNI, HTTP Host, or DNS question).
    pub fn hostname(&self) -> Option<&str> {
        self.tls
            .as_ref()
            .and_then(|t| t.sni.as_deref())
            .or_else(|| self.http.as_ref().and_then(|h| h.host.as_deref()))
            .or_else(|| self.dns.as_ref().and_then(|d| d.query_name.as_deref()))
    }
}

/// A parsed packet enriched with capture context; this is what the inspector shows.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketRecord {
    pub id: PacketId,
    pub flow_id: Option<FlowId>,
    pub timestamp_us: u64,
    pub direction: Direction,
    pub cast: Cast,
    pub class: TrafficClass,
    #[serde(flatten)]
    pub packet: ParsedPacket,
}
