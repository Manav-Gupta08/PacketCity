//! Byte-exact frame builders. Used by unit tests (deterministic fixtures) and by the clearly
//! labelled demo source. Nothing here is used for live or PCAP traffic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::packet::MacAddr;
use crate::parser::{ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};

const DEFAULT_TTL: u8 = 64;
const TCP_WINDOW: u16 = 64240;

#[derive(Clone, Copy, Debug)]
pub struct Endpoints {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

impl Endpoints {
    pub fn reversed(&self) -> Self {
        Self { src_mac: self.dst_mac, dst_mac: self.src_mac, src_ip: self.dst_ip, dst_ip: self.src_ip }
    }
}

pub fn ethernet(dst: MacAddr, src: MacAddr, ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ether_type.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut h = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, ttl, protocol, 0, 0];
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let checksum = internet_checksum(&h);
    h[10..12].copy_from_slice(&checksum.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

pub fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x60, 0, 0, 0];
    h.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    h.push(next_header);
    h.push(hop_limit);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h.extend_from_slice(payload);
    h
}

pub fn tcp(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(20 + payload.len());
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push(5 << 4);
    s.push(flags);
    s.extend_from_slice(&TCP_WINDOW.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(payload);
    s
}

pub fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(8 + payload.len());
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    s.extend_from_slice(&[0, 0]);
    s.extend_from_slice(payload);
    s
}

pub fn icmp_echo(v6: bool, request: bool, id: u16, seq: u16) -> Vec<u8> {
    let icmp_type = match (v6, request) {
        (false, true) => 8,
        (false, false) => 0,
        (true, true) => 128,
        (true, false) => 129,
    };
    let mut m = vec![icmp_type, 0, 0, 0];
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&[0u8; 32]);
    m
}

pub fn arp(operation: u16, sender_mac: MacAddr, sender_ip: Ipv4Addr, target_mac: MacAddr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0, 1, 0x08, 0x00, 6, 4];
    p.extend_from_slice(&operation.to_be_bytes());
    p.extend_from_slice(&sender_mac.0);
    p.extend_from_slice(&sender_ip.octets());
    p.extend_from_slice(&target_mac.0);
    p.extend_from_slice(&target_ip.octets());
    p
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&0x0100u16.to_be_bytes());
    m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(name, &mut m);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m
}

/// A-record response whose answer name is a compression pointer back to the question.
pub fn dns_response_a(id: u16, name: &str, address: Ipv4Addr) -> Vec<u8> {
    let mut m = dns_query(id, name, 1);
    m[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    m[6..8].copy_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4]);
    m.extend_from_slice(&address.octets());
    m
}

pub fn tls_client_hello(sni: &str) -> Vec<u8> {
    tls_client_hello_padded(sni, 0)
}

/// ClientHello with a padding extension of `padding` bytes placed *before* the SNI, as large
/// key shares or randomised extension order do in real browsers.
pub fn tls_client_hello_padded(sni: &str, padding: usize) -> Vec<u8> {
    let mut ext = Vec::new();
    if padding > 0 {
        ext.extend_from_slice(&21u16.to_be_bytes());
        ext.extend_from_slice(&(padding as u16).to_be_bytes());
        ext.resize(ext.len() + padding, 0);
    }
    let name = sni.as_bytes();
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
    ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext.extend_from_slice(name);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x5A; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![22, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

pub fn tls_application_data(len: usize) -> Vec<u8> {
    let mut rec = vec![23, 0x03, 0x03];
    rec.extend_from_slice(&(len as u16).to_be_bytes());
    rec.resize(5 + len, 0xAB);
    rec
}

pub fn http_get(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: packetcity-synth\r\n\r\n").into_bytes()
}

/// DHCPREQUEST from `client` carrying host name option 12.
pub fn dhcp_request(client: MacAddr, hostname: &str) -> Vec<u8> {
    let mut m = vec![1, 1, 6, 0, 0x12, 0x34, 0x56, 0x78];
    m.resize(28, 0);
    m.extend_from_slice(&client.0);
    m.resize(236, 0);
    m.extend_from_slice(&[0x63, 0x82, 0x53, 0x63, 53, 1, 3, 12, hostname.len() as u8]);
    m.extend_from_slice(hostname.as_bytes());
    m.push(255);
    m
}

/// NetBIOS name registration (broadcast) for a workstation name.
pub fn nbns_registration(name: &str, address: Ipv4Addr) -> Vec<u8> {
    let mut m = vec![0x80, 0x01, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1];
    m.push(32);
    let mut raw = [b' '; 16];
    for (dst, src) in raw.iter_mut().zip(name.to_ascii_uppercase().bytes().take(15)) {
        *dst = src;
    }
    raw[15] = 0x00;
    for b in raw {
        m.push(b'A' + (b >> 4));
        m.push(b'A' + (b & 0x0F));
    }
    m.push(0);
    m.extend_from_slice(&[0, 0x20, 0, 1]);
    m.extend_from_slice(&[0xC0, 0x0C, 0, 0x20, 0, 1, 0, 0x04, 0x93, 0xE0, 0, 6, 0, 0]);
    m.extend_from_slice(&address.octets());
    m
}

/// mDNS announcement: one PTR answer plus the host's A record in the additional section.
pub fn mdns_announcement(host: &str, address: Ipv4Addr) -> Vec<u8> {
    let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 1];
    encode_name("_workstation._tcp.local", &mut m);
    m.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0x11, 0x94]);
    let mut target = Vec::new();
    encode_name(host, &mut target);
    m.extend_from_slice(&(target.len() as u16).to_be_bytes());
    m.extend_from_slice(&target);
    encode_name(host, &mut m);
    m.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4]);
    m.extend_from_slice(&address.octets());
    m
}

fn ip_packet(ep: &Endpoints, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let (ether_type, packet) = match (ep.src_ip, ep.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (ETHERTYPE_IPV4, ipv4(s, d, protocol, DEFAULT_TTL, payload)),
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let next = if protocol == IPPROTO_ICMP { IPPROTO_ICMPV6 } else { protocol };
            (ETHERTYPE_IPV6, ipv6(s, d, next, DEFAULT_TTL, payload))
        }
        _ => panic!("synth endpoints must share an IP version"),
    };
    ethernet(ep.dst_mac, ep.src_mac, ether_type, &packet)
}

pub fn tcp_frame(ep: &Endpoints, sp: u16, dp: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    ip_packet(ep, IPPROTO_TCP, &tcp(sp, dp, seq, ack, flags, payload))
}

pub fn udp_frame(ep: &Endpoints, sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    ip_packet(ep, IPPROTO_UDP, &udp(sp, dp, payload))
}

pub fn icmp_echo_frame(ep: &Endpoints, request: bool, id: u16, seq: u16) -> Vec<u8> {
    ip_packet(ep, IPPROTO_ICMP, &icmp_echo(ep.src_ip.is_ipv6(), request, id, seq))
}

pub fn arp_request_frame(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let body = arp(1, sender_mac, sender_ip, MacAddr::default(), target_ip);
    ethernet(MacAddr::BROADCAST, sender_mac, ETHERTYPE_ARP, &body)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
